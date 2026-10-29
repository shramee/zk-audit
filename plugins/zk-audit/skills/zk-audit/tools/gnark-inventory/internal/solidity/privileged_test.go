package solidity

import (
	"strings"
	"testing"
)

// A pool with an owner checked inline, a relayer modifier, an OpenZeppelin
// style upgradeable registry with roles, and an ungated verifier setter.
const privSrc = `
pragma solidity ^0.8.20;
interface IVerifier { function verifyProof(bytes calldata p, uint256[3] calldata i) external view; }

contract Vault {
    IVerifier public verifier;
    mapping(uint256 => bool) public knownRoots;
    mapping(uint256 => bool) public spent;
    address public owner;
    address public relayer;
    uint256 public fee;
    uint256 public constant MAX_FEE = 100;

    modifier onlyRelayer() { require(msg.sender == relayer, "relayer"); _; }

    constructor(address v) { owner = msg.sender; verifier = IVerifier(v); }

    function setVerifier(address v) external {
        require(msg.sender == owner, "owner");
        verifier = IVerifier(v);
    }

    function addRoot(uint256 root) external {
        if (msg.sender != owner) revert();
        knownRoots[root] = true;
    }

    function setFee(uint256 f) external onlyRelayer { fee = f; }

    function setRelayer(address r) public { relayer = r; }

    function deposit(uint256 root) external payable { knownRoots[root] = true; }

    function withdraw(bytes calldata proof, uint256 root, uint256 nf, address to) external {
        require(knownRoots[root], "root");
        require(!spent[nf], "spent");
        verifier.verifyProof(proof, [root, nf, uint256(uint160(to))]);
        spent[nf] = true;
        payable(to).transfer(1 ether);
    }

    function _internalSet(address v) internal { verifier = IVerifier(v); }
}

contract Registry is Initializable, AccessControlUpgradeable, UUPSUpgradeable {
    bytes32 public constant UPDATER_ROLE = keccak256("UPDATER_ROLE");
    bytes32 public vkHash;

    function initialize(address admin) external initializer { _grantRole(DEFAULT_ADMIN_ROLE, admin); }

    function setVk(bytes32 h) external onlyRole(UPDATER_ROLE) { vkHash = h; }

    function rotate(address a) external {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "admin");
        _grantRole(UPDATER_ROLE, a);
    }

    function _authorizeUpgrade(address impl) internal override onlyRole(DEFAULT_ADMIN_ROLE) {}

    function exec(address target, bytes calldata data) external onlyOwner {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
    }
}
`

func TestScanPrivileged(t *testing.T) {
	r := ScanSource("Vault.sol", privSrc)
	got := map[string]Privileged{}
	for _, p := range r.Privileged {
		got[p.Contract+"."+p.Function] = p
	}
	want := map[string]struct{ party, powers string }{
		"Vault.setVerifier": {"owner", "verifier"},
		"Vault.addRoot":     {"owner", "root"},
		"Vault.setFee":      {"relayer", "config"},
		"Vault.setRelayer":  {"anyone", "authority"}, // ungated authority write
		"Registry.setVk":    {"role:UPDATER_ROLE", "vk"},
		"Registry.rotate":   {"role:DEFAULT_ADMIN_ROLE", "authority"},
		"Registry.exec":     {"owner", "upgrade"},
		// whoever calls an initializer first becomes the admin
		"Registry.initialize": {"deployer", "authority"},
	}
	for k, w := range want {
		p, ok := got[k]
		if !ok {
			t.Errorf("%s not reported as privileged (got %v)", k, keys(got))
			continue
		}
		if p.Party != w.party || strings.Join(p.Powers, ",") != w.powers {
			t.Errorf("%s: party %q powers %v, want %q %s (gate %q)", k, p.Party, p.Powers, w.party, w.powers, p.Gate)
		}
	}
	for _, k := range []string{"Vault.deposit", "Vault.withdraw", "Vault._internalSet", "Vault.constructor"} {
		if _, ok := got[k]; ok {
			t.Errorf("%s must not be listed: %+v", k, got[k])
		}
	}
	if g := got["Vault.setVerifier"].Gate; !strings.Contains(g, "msg.sender == owner") {
		t.Errorf("setVerifier gate %q", g)
	}
	if g := got["Vault.setVerifier"]; g.Line != 18 {
		t.Errorf("setVerifier line %d, want 18", g.Line)
	}
	roles := map[string]string{}
	for _, ro := range r.Roles {
		roles[ro.Contract+"."+ro.Name] = ro.Kind
	}
	for k, kind := range map[string]string{
		"Vault.owner": "owner", "Vault.relayer": "relayer",
		"Registry.UPDATER_ROLE": "role", "Registry.DEFAULT_ADMIN_ROLE": "role", "Registry.owner": "owner",
	} {
		if roles[k] != kind {
			t.Errorf("role %s: kind %q want %q (all %v)", k, roles[k], kind, roles)
		}
	}
	ups := map[string]bool{}
	for _, u := range r.Upgrades {
		ups[u.Contract+"."+u.Function+":"+u.Kind] = true
	}
	for _, k := range []string{"Registry.:proxy-base", "Registry.initialize:initializer", "Registry._authorizeUpgrade:authorize-upgrade", "Registry.exec:delegatecall"} {
		if !ups[k] {
			t.Errorf("missing upgrade path %s in %v", k, ups)
		}
	}
	// the privileged scan does not disturb the integration scan
	if len(r.VerifyCalls) != 1 || r.VerifyCalls[0].Function != "withdraw" {
		t.Errorf("verify calls: %+v", r.VerifyCalls)
	}
}

func TestScanPrivilegedDeterministic(t *testing.T) {
	a := ScanSource("Vault.sol", privSrc)
	for i := 0; i < 20; i++ {
		b := ScanSource("Vault.sol", privSrc)
		if len(a.Privileged) != len(b.Privileged) {
			t.Fatal("privileged count varies between runs")
		}
		for j := range a.Privileged {
			if a.Privileged[j].Gate != b.Privileged[j].Gate || a.Privileged[j].Party != b.Privileged[j].Party {
				t.Fatalf("privileged[%d] varies: %+v vs %+v", j, a.Privileged[j], b.Privileged[j])
			}
		}
	}
}

func keys(m map[string]Privileged) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
