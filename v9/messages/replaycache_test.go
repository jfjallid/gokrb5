package messages

import (
	"testing"
	"time"

	"github.com/jfjallid/gokrb5/v9/types"
)

func testAuth(cname string, ct time.Time, cusec int) types.Authenticator {
	return types.Authenticator{
		CName: types.PrincipalName{NameType: 1, NameString: []string{cname}},
		CTime: ct,
		Cusec: cusec,
	}
}

func TestReplayCache_DetectsReplay(t *testing.T) {
	c := &ReplayCache{entries: make(map[string]time.Time)}
	sname := types.PrincipalName{NameType: 2, NameString: []string{"HTTP", "host"}}
	ct := time.Now().UTC()
	a := testAuth("alice", ct, 1234)
	d := 5 * time.Minute

	if c.IsReplay(sname, a, d) {
		t.Fatal("first presentation must not be a replay")
	}
	if !c.IsReplay(sname, a, d) {
		t.Fatal("second identical presentation must be detected as a replay")
	}
}

func TestReplayCache_DistinctTuplesNotReplay(t *testing.T) {
	c := &ReplayCache{entries: make(map[string]time.Time)}
	sname := types.PrincipalName{NameType: 2, NameString: []string{"HTTP", "host"}}
	other := types.PrincipalName{NameType: 2, NameString: []string{"HOST", "host2"}}
	ct := time.Now().UTC()
	d := 5 * time.Minute

	// Same cname/sname but different cusec -> different authenticator.
	if c.IsReplay(sname, testAuth("alice", ct, 1), d) {
		t.Fatal("unexpected replay for first cusec")
	}
	if c.IsReplay(sname, testAuth("alice", ct, 2), d) {
		t.Fatal("different cusec must not be a replay")
	}
	// Different client.
	if c.IsReplay(sname, testAuth("bob", ct, 1), d) {
		t.Fatal("different cname must not be a replay")
	}
	// Different service, same client/time -> not a replay against that service.
	if c.IsReplay(other, testAuth("alice", ct, 1), d) {
		t.Fatal("different sname must not be a replay")
	}
}

func TestReplayCache_PurgeExpired(t *testing.T) {
	c := &ReplayCache{entries: make(map[string]time.Time)}
	sname := types.PrincipalName{NameType: 2, NameString: []string{"HTTP", "host"}}
	a := testAuth("alice", time.Now().UTC(), 7)

	// Insert with a negative lifetime so the entry is already expired, then force
	// a purge by moving lastPurge back beyond the throttle window.
	if c.IsReplay(sname, a, -time.Second) {
		t.Fatal("first presentation must not be a replay")
	}
	c.lastPurge = time.Now().UTC().Add(-2 * time.Second)
	// A subsequent call triggers purgeLocked, which should drop the expired entry,
	// so this is treated as fresh rather than a replay.
	if c.IsReplay(sname, a, 5*time.Minute) {
		t.Fatal("expired entry should have been purged, not flagged as replay")
	}
}
