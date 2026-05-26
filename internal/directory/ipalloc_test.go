package directory

import "testing"

func TestNextFreeIPStartsAtFirstUsable(t *testing.T) {
	cases := []struct {
		cidr string
		want string
	}{
		{cidr: "10.42.0.0/24", want: "10.42.0.1"},
		{cidr: "192.168.1.0/24", want: "192.168.1.1"},
		{cidr: "10.0.0.0/16", want: "10.0.0.1"},
		{cidr: "10.0.0.0/28", want: "10.0.0.1"},
		{cidr: "10.0.0.4/30", want: "10.0.0.5"},
	}
	for _, tc := range cases {
		t.Run(tc.cidr, func(t *testing.T) {
			got, err := NextFreeIP(tc.cidr, nil)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %s want %s", got, tc.want)
			}
		})
	}
}

func TestNextFreeIPSkipsTaken(t *testing.T) {
	got, err := NextFreeIP("10.42.0.0/24", []string{"10.42.0.1", "10.42.0.2", "10.42.0.3"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.42.0.4" {
		t.Fatalf("got %s want 10.42.0.4", got)
	}
}

func TestNextFreeIPSkipsNetworkAndBroadcast(t *testing.T) {
	if _, err := NextFreeIP("10.42.0.0/30", []string{"10.42.0.1", "10.42.0.2"}); err == nil {
		t.Fatal("expected exhaustion")
	}
}

func TestNextFreeIPSlashThirtyOne(t *testing.T) {
	got, err := NextFreeIP("10.42.0.0/31", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.42.0.0" {
		t.Fatalf("got %s want 10.42.0.0", got)
	}
	got, err = NextFreeIP("10.42.0.0/31", []string{"10.42.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.42.0.1" {
		t.Fatalf("got %s want 10.42.0.1", got)
	}
}

func TestNextFreeIPSlashThirtyTwo(t *testing.T) {
	got, err := NextFreeIP("10.42.0.5/32", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.42.0.5" {
		t.Fatalf("got %s want 10.42.0.5", got)
	}
	if _, err := NextFreeIP("10.42.0.5/32", []string{"10.42.0.5"}); err == nil {
		t.Fatal("expected exhaustion")
	}
}

func TestNextFreeIPIgnoresTakenOutsideCIDR(t *testing.T) {
	got, err := NextFreeIP("10.42.0.0/24", []string{"192.168.1.1", "10.43.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	if got != "10.42.0.1" {
		t.Fatalf("got %s want 10.42.0.1", got)
	}
}

func TestNextFreeIPRejectsInvalidInputs(t *testing.T) {
	if _, err := NextFreeIP("fd00::/64", nil); err == nil {
		t.Fatal("expected IPv6 CIDR rejection")
	}
	if _, err := NextFreeIP("not-a-cidr", nil); err == nil {
		t.Fatal("expected invalid CIDR rejection")
	}
	if _, err := NextFreeIP("10.42.0.0/24", []string{"not-an-ip"}); err == nil {
		t.Fatal("expected invalid taken IP rejection")
	}
}

func TestIsRollback(t *testing.T) {
	if !IsRollback(2, 3) {
		t.Fatal("expected rollback")
	}
	if IsRollback(3, 3) {
		t.Fatal("equal serial should be accepted")
	}
}
