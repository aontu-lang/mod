// Copyright (c) 2026 aontu-lang, MIT License.

// Command goref writes the golden vectors from the pinned upstream; its
// output must not vary between runs. See docs/contributing/verifier.md.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Varied in length, so a length-sensitive bug cannot hide behind fixed widths.
func record(i int64) []byte {
	return []byte(fmt.Sprintf("record %d", i))
}

// storage is the dense stored-hash array tlog addresses by StoredHashIndex.
type storage []tlog.Hash

func (s storage) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, 0, len(indexes))
	for _, i := range indexes {
		if i < 0 || i >= int64(len(s)) {
			return nil, fmt.Errorf("index %d out of range", i)
		}
		out = append(out, s[i])
	}
	return out, nil
}

func b64(h tlog.Hash) string { return base64.StdEncoding.EncodeToString(h[:]) }

func b64s(hs []tlog.Hash) []string {
	// Never nil: an empty proof is a real case, and must encode as [].
	out := []string{}
	for _, h := range hs {
		out = append(out, b64(h))
	}
	return out
}

type vectors struct {
	Upstream string `json:"upstream"`
	Corpus   string `json:"corpus"`

	// Upstream's own array, so the port needs no append side to check treeHash.
	StoredHashes []string `json:"storedHashes"`

	RecordHash      []recordHashCase      `json:"recordHash"`
	NodeHash        []nodeHashCase        `json:"nodeHash"`
	StoredHashIndex []storedHashIndexCase `json:"storedHashIndex"`
	StoredHashCount []storedHashCountCase `json:"storedHashCount"`
	TreeHash        []treeHashCase        `json:"treeHash"`
	CheckRecord     []checkRecordCase     `json:"checkRecord"`
	CheckTree       []checkTreeCase       `json:"checkTree"`
	Note            noteVectors           `json:"note"`
	TilePath        []tilePathCase        `json:"tilePath"`
	TileForIndex    []tileForIndexCase    `json:"tileForIndex"`
}

type recordHashCase struct {
	Data string `json:"data"` // base64 of the record bytes
	Hash string `json:"hash"`
}

type nodeHashCase struct {
	Left  string `json:"left"`
	Right string `json:"right"`
	Hash  string `json:"hash"`
}

type storedHashIndexCase struct {
	Level int   `json:"level"`
	N     int64 `json:"n"`
	Index int64 `json:"index"`
}

type storedHashCountCase struct {
	N     int64 `json:"n"`
	Count int64 `json:"count"`
}

type treeHashCase struct {
	N    int64  `json:"n"`
	Root string `json:"root"`
}

type checkRecordCase struct {
	Name  string   `json:"name"`
	T     int64    `json:"t"`
	Th    string   `json:"th"`
	N     int64    `json:"n"`
	H     string   `json:"h"`
	Proof []string `json:"proof"`
	Want  bool     `json:"want"`
}

type checkTreeCase struct {
	Name  string   `json:"name"`
	T     int64    `json:"t"`
	Th    string   `json:"th"`
	N     int64    `json:"n"`
	H     string   `json:"h"`
	Proof []string `json:"proof"`
	Want  bool     `json:"want"`
}

type noteVectors struct {
	Seed        string          `json:"seed"`
	VerifierKey string          `json:"verifierKey"`
	Name        string          `json:"name"`
	KeyHash     uint32          `json:"keyHash"`
	Signed      []noteCase      `json:"signed"`
	Trees       []treeNoteCase  `json:"trees"`
	Malformed   []malformedCase `json:"malformed"`
}

type noteCase struct {
	Name string `json:"name"`
	Text string `json:"text"`
	Msg  string `json:"msg"`
	Want bool   `json:"want"`
}

type treeNoteCase struct {
	Text   string `json:"text"`
	Origin string `json:"origin"`
	N      int64  `json:"n"`
	Hash   string `json:"hash"`
	Want   bool   `json:"want"`
}

type malformedCase struct {
	Name string `json:"name"`
	Msg  string `json:"msg"`
}

type tilePathCase struct {
	H    int    `json:"h"`
	L    int    `json:"l"`
	N    int64  `json:"n"`
	W    int    `json:"w"`
	Path string `json:"path"`
}

type tileForIndexCase struct {
	H     int    `json:"h"`
	Index int64  `json:"index"`
	L     int    `json:"tileL"`
	N     int64  `json:"tileN"`
	W     int    `json:"tileW"`
	Path  string `json:"path"`
}

// Chosen for shape: degenerate, ragged, perfect, and past a single tile.
var sizes = []int64{1, 2, 3, 4, 5, 6, 7, 8, 11, 13, 16, 17, 100, 1000}

func main() {
	const maxN = 1000

	var store storage
	leaf := make([]tlog.Hash, 0, maxN)
	for i := int64(0); i < maxN; i++ {
		h := tlog.RecordHash(record(i))
		leaf = append(leaf, h)
		hashes, err := tlog.StoredHashesForRecordHash(i, h, store)
		if err != nil {
			fatal(err)
		}
		store = append(store, hashes...)
	}

	v := vectors{
		StoredHashes: b64s(store),
		Upstream:     "golang.org/x/mod@v0.32.0 sumdb/tlog",
		Corpus:       `record i is the ASCII bytes of "record <i>", i from 0`,
	}

	// --- leaf and node hashing -------------------------------------
	for _, i := range []int64{0, 1, 2, 9, 10, 99, 100, 999} {
		v.RecordHash = append(v.RecordHash, recordHashCase{
			Data: base64.StdEncoding.EncodeToString(record(i)),
			Hash: b64(tlog.RecordHash(record(i))),
		})
	}
	// The empty record still hashes the leaf prefix.
	v.RecordHash = append(v.RecordHash, recordHashCase{
		Data: "",
		Hash: b64(tlog.RecordHash(nil)),
	})

	for _, p := range [][2]int64{{0, 1}, {1, 0}, {0, 0}, {5, 99}} {
		v.NodeHash = append(v.NodeHash, nodeHashCase{
			Left:  b64(leaf[p[0]]),
			Right: b64(leaf[p[1]]),
			Hash:  b64(tlog.NodeHash(leaf[p[0]], leaf[p[1]])),
		})
	}

	// --- stored-hash addressing ------------------------------------
	for level := 0; level < 4; level++ {
		for n := int64(0); n < 6; n++ {
			v.StoredHashIndex = append(v.StoredHashIndex, storedHashIndexCase{
				Level: level, N: n, Index: tlog.StoredHashIndex(level, n),
			})
		}
	}
	// Past 2^31, where a JavaScript bitwise operator would wrap.
	for _, big := range []int64{1 << 31, 1 << 32, 1 << 40} {
		for level := 0; level < 3; level++ {
			v.StoredHashIndex = append(v.StoredHashIndex, storedHashIndexCase{
				Level: level, N: big, Index: tlog.StoredHashIndex(level, big),
			})
		}
	}
	for _, n := range append(append([]int64{}, sizes...),
		1<<31, 1<<32, 1<<40) {
		v.StoredHashCount = append(v.StoredHashCount, storedHashCountCase{
			N: n, Count: tlog.StoredHashCount(n),
		})
	}

	// --- tree roots -------------------------------------------------
	roots := map[int64]tlog.Hash{}
	for _, n := range sizes {
		th, err := tlog.TreeHash(n, store)
		if err != nil {
			fatal(err)
		}
		roots[n] = th
		v.TreeHash = append(v.TreeHash, treeHashCase{N: n, Root: b64(th)})
	}

	// --- inclusion proofs -------------------------------------------
	for _, t := range sizes {
		for _, n := range interesting(t) {
			p, err := tlog.ProveRecord(t, n, store)
			if err != nil {
				fatal(err)
			}
			th := roots[t]
			add := func(name string, t int64, th tlog.Hash, n int64, h tlog.Hash, p tlog.RecordProof) {
				v.CheckRecord = append(v.CheckRecord, checkRecordCase{
					Name: name, T: t, Th: b64(th), N: n, H: b64(h),
					Proof: b64s(p), Want: tlog.CheckRecord(p, t, th, n, h) == nil,
				})
			}
			add(fmt.Sprintf("t=%d n=%d", t, n), t, th, n, leaf[n], p)

			// The rejections are what pin the algorithm.
			if len(p) > 0 {
				// One sibling hash corrupted.
				bad := append(tlog.RecordProof{}, p...)
				bad[0] = flip(bad[0])
				add(fmt.Sprintf("t=%d n=%d corrupt-proof", t, n), t, th, n, leaf[n], bad)

				// A proof of the right length for the wrong leaf.
				short := append(tlog.RecordProof{}, p[:len(p)-1]...)
				add(fmt.Sprintf("t=%d n=%d short-proof", t, n), t, th, n, leaf[n], short)
			}
			// Right proof, wrong root.
			add(fmt.Sprintf("t=%d n=%d wrong-root", t, n), t, flip(th), n, leaf[n], p)
			// Right proof, wrong leaf.
			add(fmt.Sprintf("t=%d n=%d wrong-leaf", t, n), t, th, n, flip(leaf[n]), p)
		}
	}

	// --- consistency proofs ------------------------------------------
	for _, t := range sizes {
		for _, n := range interesting(t) {
			if n < 1 {
				continue
			}
			p, err := tlog.ProveTree(t, n, store)
			if err != nil {
				fatal(err)
			}
			th, h := roots[t], mustRoot(store, n)
			add := func(name string, t int64, th tlog.Hash, n int64, h tlog.Hash, p tlog.TreeProof) {
				v.CheckTree = append(v.CheckTree, checkTreeCase{
					Name: name, T: t, Th: b64(th), N: n, H: b64(h),
					Proof: b64s(p), Want: tlog.CheckTree(p, t, th, n, h) == nil,
				})
			}
			add(fmt.Sprintf("t=%d n=%d", t, n), t, th, n, h, p)

			if len(p) > 0 {
				bad := append(tlog.TreeProof{}, p...)
				bad[0] = flip(bad[0])
				add(fmt.Sprintf("t=%d n=%d corrupt-proof", t, n), t, th, n, h, bad)

				short := append(tlog.TreeProof{}, p[:len(p)-1]...)
				add(fmt.Sprintf("t=%d n=%d short-proof", t, n), t, th, n, h, short)
			}
			add(fmt.Sprintf("t=%d n=%d wrong-new-root", t, n), t, flip(th), n, h, p)
			add(fmt.Sprintf("t=%d n=%d wrong-old-root", t, n), t, th, n, flip(h), p)
		}
	}

	// --- tiles --------------------------------------------------------
	for _, h := range []int{1, 2, 8} {
		for _, l := range []int{0, 1, 2} {
			for _, n := range []int64{0, 1, 2, 999, 1000, 1001, 1000000} {
				for _, w := range []int{0, 1, 1 << h} {
					t := tlog.Tile{H: h, L: l, N: n, W: w}
					if w == 0 || w > 1<<h {
						continue
					}
					v.TilePath = append(v.TilePath, tilePathCase{
						H: h, L: l, N: n, W: w, Path: t.Path(),
					})
				}
			}
		}
	}
	for _, h := range []int{1, 2, 8} {
		for _, index := range []int64{0, 1, 2, 3, 7, 8, 63, 64, 100, 1000} {
			t := tlog.TileForIndex(h, index)
			v.TileForIndex = append(v.TileForIndex, tileForIndexCase{
				H: h, Index: index, L: t.L, N: t.N, W: t.W, Path: t.Path(),
			})
		}
	}

	// --- signed notes -------------------------------------------------
	v.Note = noteVectorsFor(roots)

	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stdout.Write(append(out, '\n')); err != nil {
		fatal(err)
	}
}

// interesting is the ends, the middle, and either side of the maxpow2 split.
func interesting(t int64) []int64 {
	set := map[int64]bool{0: true, t - 1: true, t / 2: true}
	k := int64(1)
	for k*2 < t {
		k *= 2
	}
	if k-1 >= 0 {
		set[k-1] = true
	}
	if k < t {
		set[k] = true
	}
	out := []int64{}
	for i := int64(0); i < t; i++ {
		if set[i] {
			out = append(out, i)
		}
	}
	return out
}

func mustRoot(store storage, n int64) tlog.Hash {
	h, err := tlog.TreeHash(n, store)
	if err != nil {
		fatal(err)
	}
	return h
}

// flip inverts one bit: the smallest corruption a verifier must catch.
func flip(h tlog.Hash) tlog.Hash {
	h[0] ^= 0x01
	return h
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "goref:", err)
	os.Exit(1)
}

// Public test material, so that anyone can re-derive the vectors.
const noteSeed = "0123456789abcdef0123456789abcdef"

const noteName = "aontu.example/transparency"

func noteVectorsFor(roots map[int64]tlog.Hash) noteVectors {
	priv := ed25519.NewKeyFromSeed([]byte(noteSeed))
	pub := priv.Public().(ed25519.PublicKey)

	// The key hash covers the algorithm byte as well as the key.
	encoded := append([]byte{1}, pub...)
	h := sha256.Sum256(append(append([]byte(noteName), '\n'), encoded...))
	kh := binary.BigEndian.Uint32(h[:])

	vkey := fmt.Sprintf("%s+%08x+%s", noteName, kh,
		base64.StdEncoding.EncodeToString(encoded))

	signer, err := note.NewSigner(fmt.Sprintf("PRIVATE+KEY+%s+%08x+%s",
		noteName, kh,
		base64.StdEncoding.EncodeToString(append([]byte{1}, priv.Seed()...))))
	if err != nil {
		fatal(err)
	}

	out := noteVectors{
		Seed: noteSeed, VerifierKey: vkey, Name: noteName, KeyHash: kh,
	}

	sign := func(name, text string) {
		msg, err := note.Sign(&note.Note{Text: text}, signer)
		if err != nil {
			fatal(err)
		}
		out.Signed = append(out.Signed, noteCase{
			Name: name, Text: text, Msg: string(msg), Want: true,
		})
	}
	sign("one-line", "hello\n")
	sign("multi-line", "line one\nline two\nline three\n")
	sign("utf8", "café — ☃\n")

	// Well-formed, known key, signature over other text: refused.
	tampered := out.Signed[0]
	out.Signed = append(out.Signed, noteCase{
		Name: "text-tampered",
		Text: "hello!\n",
		Msg:  "hello!\n" + tampered.Msg[len(tampered.Text):],
		Want: false,
	})

	// Checkpoint bodies, in the shape a tree head takes.
	for _, n := range []int64{1, 13, 1000} {
		text := fmt.Sprintf("%s\n%d\n%s\n", noteName, n, b64(roots[n]))
		out.Trees = append(out.Trees, treeNoteCase{
			Text: text, Origin: noteName, N: n, Hash: b64(roots[n]), Want: true,
		})
	}
	// Each parses as a number; a tree size has one spelling.
	for _, bad := range []string{"007", "+7", " 7", "7 ", "1e3", ""} {
		text := fmt.Sprintf("%s\n%s\n%s\n", noteName, bad, b64(roots[13]))
		out.Trees = append(out.Trees, treeNoteCase{
			Text: text, Origin: noteName, Want: false,
		})
	}
	// A wrong origin is another log.
	out.Trees = append(out.Trees, treeNoteCase{
		Text:   fmt.Sprintf("other.example\n13\n%s\n", b64(roots[13])),
		Origin: noteName, Want: false,
	})

	out.Malformed = []malformedCase{
		{"no-signature-block", "hello\n"},
		{"empty", ""},
		{"no-trailing-newline", "hello\n\n— " + noteName + " abcd"},
		{"bad-prefix", "hello\n\nx " + noteName + " abcd\n"},
		{"control-character", "hel\x01lo\n\n— " + noteName + " abcd\n"},
	}

	return out
}
