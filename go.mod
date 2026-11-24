module golang.zx2c4.com/wireguard

go 1.20

require (
	golang.org/x/crypto v0.13.0
	golang.org/x/net v0.15.0
	golang.org/x/sys v0.12.0
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2
	gvisor.dev/gvisor v0.0.0-20230927004350-cbd86285d259
)

require (
	github.com/google/btree v1.0.1 // indirect
	github.com/wolfssl/go-wolfssl v0.0.0
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
)

// go-wolfssl is pinned to branch pinned-for-wolfguard @ 7d131fa in a dedicated
// worktree, not to ~/GIT/go-wolfssl, so builds do not drift with that clone.
// That branch is master plus one commit fixing kyber.go to include wc_mlkem.h.
// Reconciling the fork with upstream is tracked separately; see the bead.
replace github.com/wolfssl/go-wolfssl => /home/langwei/WORKTREES/go-wolfssl/pinned-for-wolfguard
