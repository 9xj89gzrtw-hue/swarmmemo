package trust

import "math/bits"

// Assessed roots (RFC0015 §13 "Raise your standing", C144): a priced entity
// whose value is not one fixed price but an assessment made when the board
// checked it, carried on its proof record (assessed) and bounded here by the
// pricing table. Three kinds, from trust parameter version 5 (RootsVersion):
//
//   - wallet: an EVM address that signed an EIP-4361 (CAIP-122) challenge
//     naming the agent's fingerprint. Assessed at Corroborate's resolver
//     total for the address, in cents: personhood credentials and onchain
//     history count through it. Capped at min(forge, rent).
//   - github: a GitHub account that published the agent's challenge in a
//     public gist. Assessed by GitHubCents (account age and public
//     activity, both saturating). Capped at min(forge, rent).
//   - pow: proof of work, solutions to server-issued SHA-256 challenges.
//     Assessed in work units (2^20 expected hashes each); units_per_cent is
//     the GPU price of a cent of work, and the contribution saturates:
//     cap × v / (v + cap) for v cents of work, so it never reaches the cap,
//     which is far below the tier bands.
//
// An assessed root counts while its proof is verified and was checked within
// proof_fresh_days (a wallet's resolver answer, a GitHub recheck, a pow
// account's last solution). The root key comes with the record: github: and
// the numeric user id (a renamed account keeps its root), wallet: and the
// CAIP-10 address, pow: and the key.

// Assessment rules of a pricing row (ProofPrice.Assess).
const (
	AssessCapped     = "capped"     // min(cap, assessed / units_per_cent)
	AssessSaturating = "saturating" // cap × v / (v + cap), v = assessed / units_per_cent
	AssessDomain     = "domain"     // age_cents × ramp(registration age) + rank_cents × max(0, 1 − log₁₀(rank)/6)
)

// assessedKinds are the optional pricing rows and the rule each must use:
// C144's three, then C326's (ProofsVersion), all capped.
var assessedKinds = map[string]string{"wallet": AssessCapped, "github": AssessCapped, "pow": AssessSaturating,
	"google": AssessCapped, "x": AssessCapped, "discord": AssessCapped, "telegram": AssessCapped, "reddit": AssessCapped,
	"huggingface": AssessCapped, "farcaster": AssessCapped, "ens": AssessCapped, "npm": AssessCapped, "pypi": AssessCapped,
	"bond": AssessCapped}

// AssessedKinds lists the assessed root kinds in a stable order.
func AssessedKinds() []string {
	return []string{"wallet", "github", "pow", "google", "x", "discord", "telegram", "reddit", "huggingface", "farcaster", "ens", "npm", "pypi", "bond"}
}

// assessedMax bounds an assessment the run reads, so cap × assessed and
// assessed + cap × units_per_cent stay far inside int64.
const assessedMax = 1e15

// PowUnitBits is the size of one proof-of-work unit: 2^20 expected hashes.
const PowUnitBits = 20

// assessedRows are the assessed pricing rows (C144, RFC 0021 §10).
// The numbers, in US cents, and why:
//
//   - wallet: forge 5000 (a wallet with personhood credentials and years of
//     paid onchain history), rent 600 (Corroborate's own per-credential
//     prices already apply min(forge, rent); the row's 600 keeps one wallet
//     below theta1, 750, so a wallet alone never buys band 1, RFC0015 §3.5).
//   - github: forge 2000 (aged accounts with history sell for about $10 to
//     $30), rent 300 (borrowing an account long enough to publish a gist is
//     cheap). GitHubCents never exceeds 300.
//   - pow: forge = rent = 50 (half a dollar of rented GPU time; v(s) is 0
//     below v_floor_cents, 50, so work alone never buys vote weight).
//     units_per_cent 2158000: an RTX 4090 computes about 2.2e10 SHA-256 a
//     second (hashcat) and rents for about $0.35 an hour, so a cent buys
//     2.2e10 × 3600 / 35 ≈ 2.26e12 hashes, 2.158e6 units of 2^20.
func assessedRows() map[string]ProofPrice {
	return map[string]ProofPrice{
		"wallet": {Forge: 5000, Rent: 600, Curve: "none", Assess: AssessCapped, UnitsPerCent: 1},
		"github": {Forge: 2000, Rent: 300, Curve: "none", Assess: AssessCapped, UnitsPerCent: 1},
		"pow":    {Forge: 50, Rent: 50, Curve: "none", Assess: AssessSaturating, UnitsPerCent: 2158000},
	}
}

// proofRowsV9 are the price rows C326's providers add (ProofsVersion), in
// US cents, each at min(forge, rent) with the assessment (the provider's
// value inputs, internal/proofs) capped there. Rent is what borrowing the
// credential long enough to prove it costs; forge what buying or making one
// does. Followers, karma and downloads are cheap to rent, so they count
// little and saturate.
//
//   - google, telegram: forge 200, rent 50. The OAuth answer has no account
//     age: a fixed 50 (phone-verified accounts sell for about $1-3).
//   - discord: forge 500, rent 100: age from the snowflake id.
//   - x: forge 1500, rent 150: age, plus followers (saturating).
//   - reddit: forge 2000, rent 200: aged high-karma accounts sell for
//     $10-50; age plus karma.
//   - huggingface: forge 1000, rent 150: age plus followers.
//   - farcaster: forge 1000, rent 200: an FID's registration and storage
//     cost dollars; age plus followers.
//   - ens: forge 500, rent 200: a name costs at least $5 a year; a base for
//     holding one plus its age.
//   - npm, pypi: forge 1000, rent 200: an established package; age plus
//     monthly downloads (saturating: downloads are cheap to inflate).
//   - bond: forge = rent = 500: a refundable USDC deposit counts at face
//     value up to $5, and a penalty burns it.
//
// And C320c's wallet row: version 8's, plus fallback_cents 50
// (WalletFallbackCents).
func proofRowsV9() map[string]ProofPrice {
	row := func(forge, rent int64) ProofPrice {
		return ProofPrice{Forge: forge, Rent: rent, Curve: "none", Assess: AssessCapped, UnitsPerCent: 1}
	}
	wallet := assessedRows()["wallet"]
	wallet.FallbackCents = WalletFallbackCents
	return map[string]ProofPrice{
		"google": row(200, 50), "telegram": row(200, 50), "discord": row(500, 100), "x": row(1500, 150),
		"reddit": row(2000, 200), "huggingface": row(1000, 150), "farcaster": row(1000, 200), "ens": row(500, 200),
		"npm": row(1000, 200), "pypi": row(1000, 200), "bond": row(500, 500), "wallet": wallet,
	}
}

// WalletFallbackCents is the wallet row's fallback_cents (C320c): what a
// verified wallet signature prices at while Corroborate's resolver has no
// value for the address. On prod every verified wallet assessed 0: the
// resolver prices personhood credentials and onchain history, and agent
// wallets mostly have neither, so a proof that costs a key and a signature
// counted nothing. 50¢ is the pow row's ceiling: control of a fresh key is
// about as cheap to fake as half a dollar of hashing, and below v_floor
// (50¢ alone votes at v(50) ≈ 0.49, never more). The same floor bounds what
// a payee's payout address backs of settled USDC paid to it (RFC 0021 §7).
const WalletFallbackCents = 50

// AccountCents is an account's assessment from its value inputs, in cents:
// ageCents × ramp(ageDays, halfLifeDays) plus countCents × n / (n + half)
// for a public count n (followers, karma, downloads), both saturating, so
// it never exceeds ageCents + countCents. A negative input counts 0.
func AccountCents(ageDays, ageCents, halfLifeDays, n, countCents, half int64) int64 {
	var c int64
	if ageCents > 0 && halfLifeDays > 0 {
		c = ageCents * curves{}.ramp(DayFactor(halfLifeDays), max(0, ageDays)) / 1e6
	}
	if n = min(max(0, n), 1e12); countCents > 0 && half > 0 && n > 0 {
		c += mulDiv(countCents, n, n+half)
	}
	return c
}

// AssessedContribution is what an assessed root adds, in cents, under its
// pricing row: the rule of RootsVersion's doc, integer and exact.
//
// A capped row's fallback_cents (the wallet row, from ProofsVersion) is the
// least a verified, fresh proof of that kind prices at, within the cap:
// what the verified signature alone is worth while the resolver has no
// value for it (not configured, or no credentials behind the address). The
// run counts that floor once per (kind, node root) (C492): see
// AssessedValue.
func AssessedContribution(price ProofPrice, assessed int64) int64 {
	v := AssessedValue(price, assessed)
	if price.UnitsPerCent > 0 && price.Assess == AssessCapped {
		return max(v, min(price.Forge, price.Rent, max(0, price.FallbackCents)))
	}
	return v
}

// AssessedValue is AssessedContribution without a capped row's
// fallback_cents: what the assessment itself is worth. The floor prices
// control of a key, which is free to make again, so a node root's claims of
// one kind count it once, on its best claim; its other claims of that kind
// price at this value (C492): an empty wallet beside another adds nothing,
// while value a wallet proves beyond the floor (real balances) still
// stacks across distinct wallets.
func AssessedValue(price ProofPrice, assessed int64) int64 {
	if price.UnitsPerCent <= 0 || assessed <= 0 {
		return 0
	}
	ceiling := min(price.Forge, price.Rent)
	assessed = min(assessed, assessedMax)
	switch price.Assess {
	case AssessCapped:
		return min(ceiling, assessed/price.UnitsPerCent)
	case AssessSaturating:
		return mulDiv(ceiling, assessed, assessed+ceiling*price.UnitsPerCent)
	}
	return 0
}

// GitHub assessment constants: an account's age counts up to GitHubAgeCents
// (a ramp with a one-year half-life), its public repositories and followers
// up to GitHubActivityCents (s / (s + GitHubActivityHalf)), so the sum stays
// within the github row's rent (300).
const (
	GitHubAgeCents      = 200
	GitHubActivityCents = 100
	GitHubActivityHalf  = 20
	githubAgeHalfLife   = 365
)

// GitHubCents is a GitHub account's assessment in cents: its age (days since
// GitHub's created_at) and public activity (public repositories plus
// followers), both saturating. Never more than GitHubAgeCents +
// GitHubActivityCents.
func GitHubCents(ageDays, repos, followers int64) int64 {
	cv := curves{}
	age := GitHubAgeCents * cv.ramp(DayFactor(githubAgeHalfLife), max(0, ageDays)) / 1e6
	s := min(max(0, repos), 1e6) + min(max(0, followers), 1e6)
	return age + GitHubActivityCents*s/(s+GitHubActivityHalf)
}

// PowUnits is the work of one solution at bits leading zero bits, in units
// of 2^PowUnitBits expected hashes (0 below PowUnitBits).
func PowUnits(bits int64) int64 {
	if bits < PowUnitBits || bits > 62 {
		return 0
	}
	return int64(1) << (bits - PowUnitBits)
}

// DomainContribution is a domain root's price in cents (RFC 0021 §10):
// age_cents × ramp(registration age, the row's half-life) plus rank_cents ×
// max(0, 1 − log₁₀(rank)/6), at most min(forge, rent). An unknown
// registration time (registered ≤ 0) or rank (≤ 0: unlisted, or not
// fetched) counts 0: rank 1 is worth 400¢, 100 266¢, 10,000 133¢. While
// neither signal is known the domain prices at the row's fallback_cents
// (the old flat domain value), within the same cap; from version 13 a run
// counts that floor once per node root (C515).
func DomainContribution(price ProofPrice, ageDays, registered, rank int64) int64 {
	if registered <= 0 && rank <= 0 {
		return min(price.FallbackCents, price.Forge, price.Rent)
	}
	var c int64
	if registered > 0 {
		c += price.AgeCents * curves{}.ramp(price.DayFactorPPM, max(0, ageDays)) / 1e6
	}
	if rank > 0 {
		if l := Log10PPM(rank); l < 6e6 {
			c += mulDiv(price.RankCents, 6e6-l, 6e6)
		}
	}
	return min(c, min(price.Forge, price.Rent))
}

// log2Ten is log₂(10) in Q30, rounded.
const log2Ten = 3566893132

// Log10PPM is ⌊1e6 × log₁₀(n)⌋ for n ≥ 1 in integers: log₂(n) with 30
// fractional bits by repeated squaring (Q62), divided by log₂(10) in Q30.
// scripts/trust/recompute.py runs the same steps.
func Log10PPM(n int64) int64 {
	if n <= 1 {
		return 0
	}
	k := int64(bits.Len64(uint64(n)) - 1)
	y := uint64(n) << (62 - k) // n / 2^k in Q62, in [2^62, 2^63)
	var frac int64
	for i := 0; i < 30; i++ {
		hi, lo := bits.Mul64(y, y)
		y = hi<<2 | lo>>62 // y² in Q62
		frac <<= 1
		if y >= 1<<63 {
			frac |= 1
			y >>= 1
		}
	}
	return mulDiv(k<<30|frac, 1e6, log2Ten)
}
