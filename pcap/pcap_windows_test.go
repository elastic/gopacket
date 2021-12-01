// Copyright 2012 Google, Inc. All rights reserved.
// Copyright 2009-2011 Andreas Krennmair. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcap

import "testing"

func TestReloadWinPCAP(t *testing.T) {
	for _, test := range []struct {
		name string
		fn   func(*testing.T)
	}{
		{"PcapNonexistentFile", TestPcapNonexistentFile},
		{"PcapFileRead", TestPcapFileRead},
		{"BPF", TestBPF},
		// {"BPFInstruction", TestBPFInstruction}, // This test is flakey on Windows wqith Npcap even without the DLL reloading.
		{"PCAPGoWrite", TestPCAPGoWrite},
		{"PCAPGoNgWrite", TestPCAPGoNgWrite},
	} {
		err := UnloadWinPCAP()
		if err != nil {
			t.Errorf("unexpected error unloading WinPCAP: %v", err)
			continue
		}
		err = LoadWinPCAP()
		if err != nil {
			t.Errorf("unexpected error reloading WinPCAP: %v", err)
			continue
		}
		t.Run(test.name, test.fn)
	}
}
