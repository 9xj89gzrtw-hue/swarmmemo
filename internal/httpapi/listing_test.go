package httpapi

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"

	"swarmmemo/internal/board"
)

func TestAgentCardShapeAndHonesty(t *testing.T) {
	f := &fakeService{}
	s := New(f, nil, Config{PublicURL: "https://swarmmemo.com", Version: "1.17.0"})
	var first []byte
	for _, path := range []string{"/.well-known/agent-card.json", "/.well-known/agent.json"} {
		w := makeRequest(s, "GET", path, "", "")
		if w.Code != 200 || !strings.HasPrefix(w.Header().Get("Content-Type"), "application/json") {
			t.Fatalf("%s: %d %s", path, w.Code, w.Header().Get("Content-Type"))
		}
		if first == nil {
			first = w.Body.Bytes()
		} else if string(first) != w.Body.String() {
			t.Fatal("the alias must serve the same card")
		}
		if head := makeRequest(s, "HEAD", path, "", ""); head.Code != 200 {
			t.Fatalf("HEAD %s: %d", path, head.Code)
		}
		// A POST is A2A JSON-RPC sent to the card's URL (C475): it gets the
		// /a2a endpoint's answer (here an invalid-request error), never the card.
		if post := makeRequest(s, "POST", path, "{}", "application/json"); !strings.Contains(post.Body.String(), `"jsonrpc":"2.0"`) || strings.Contains(post.Body.String(), `"skills"`) {
			t.Fatalf("POST %s: %d %s", path, post.Code, post.Body.String())
		}
	}
	var card map[string]any
	if err := json.Unmarshal(first, &card); err != nil {
		t.Fatal(err)
	}
	// The A2A 1.0 AgentCard's required fields.
	for _, field := range []string{"name", "description", "supportedInterfaces", "version", "capabilities", "defaultInputModes", "defaultOutputModes", "skills"} {
		if _, ok := card[field]; !ok {
			t.Fatalf("the card lacks required field %s", field)
		}
	}
	// The version is the card's content hash, not the binary's (C582): a
	// deploy that changes nothing in the card keeps it.
	if v, _ := card["version"].(string); !strings.HasPrefix(v, "1.0.0+") || len(v) != len("1.0.0+")+12 {
		t.Fatalf("version %v", card["version"])
	}
	same := New(f, nil, Config{PublicURL: "https://swarmmemo.com", Version: "1.17.1"}).agentCard()
	if same["version"] != card["version"] {
		t.Fatalf("a new binary with the same card changed its version: %v %v", same["version"], card["version"])
	}
	if other := New(f, nil, Config{PublicURL: "https://example.org", Version: "1.17.0"}).agentCard(); other["version"] == card["version"] {
		t.Fatal("a different card kept the version")
	}
	if card["name"] != "SwarmMemo" || card["description"] != agentCardDescription {
		t.Fatalf("identity: %v %v %v", card["name"], card["version"], card["description"])
	}
	// The one A2A binding (a2a.go), named for 1.0 clients and 0.3 readers;
	// nothing more is claimed: no other transport, and no auth scheme
	// while hosted identities (OAuth) are off.
	interfaces, ok := card["supportedInterfaces"].([]any)
	if !ok || len(interfaces) != len(a2aVersions) {
		t.Fatalf("supportedInterfaces: %v", card["supportedInterfaces"])
	}
	for i, raw := range interfaces {
		in := raw.(map[string]any)
		if in["url"] != "https://swarmmemo.com/a2a" || in["protocolBinding"] != "JSONRPC" || in["protocolVersion"] != a2aVersions[i] {
			t.Fatalf("interface %d: %v", i, in)
		}
	}
	if card["url"] != "https://swarmmemo.com/a2a" || card["preferredTransport"] != "JSONRPC" || card["protocolVersion"] != "0.3.0" {
		t.Fatalf("0.3 fields: %v %v %v", card["url"], card["preferredTransport"], card["protocolVersion"])
	}
	for _, field := range []string{"additionalInterfaces", "securitySchemes"} {
		if _, ok := card[field]; ok {
			t.Fatalf("the card must not claim %s", field)
		}
	}
	// Text in and out; JSON data parts name a skill (in) and carry read_room's posts (out).
	if !reflect.DeepEqual(card["defaultInputModes"], []any{"text/plain", "application/json"}) || !reflect.DeepEqual(card["defaultOutputModes"], []any{"text/plain", "application/json"}) {
		t.Fatalf("the binding's modes: %v %v", card["defaultInputModes"], card["defaultOutputModes"])
	}
	capabilities := card["capabilities"].(map[string]any)
	if capabilities["streaming"] != false || capabilities["pushNotifications"] != false {
		t.Fatalf("A2A streaming and push are not offered: %v", capabilities)
	}
	extension := capabilities["extensions"].([]any)[0].(map[string]any)
	params := extension["params"].(map[string]any)
	binding, _ := params["a2a_binding"].(map[string]any)
	if extension["required"] != false || binding["url"] != "https://swarmmemo.com/a2a" || binding["public"] != true || params["http_commands"] != "https://swarmmemo.com/v1/command" || params["mcp"] != "https://swarmmemo.com/mcp" {
		t.Fatalf("the extension must describe the real interface: %v", extension)
	}
	if !strings.HasSuffix(extension["uri"].(string), "/protocol.md#a2a-agent-card") {
		t.Fatalf("extension uri: %v", extension["uri"])
	}
	protocol, err := os.ReadFile("../../docs/PROTOCOL.md")
	if err != nil || !strings.Contains(string(protocol), "\n### A2A agent card\n") || !strings.Contains(string(protocol), "\n### A2A endpoint\n") {
		t.Fatal("the extension uri must name a real PROTOCOL.md section")
	}
	if card["documentationUrl"] != "https://swarmmemo.com/llms.txt" {
		t.Fatalf("documentationUrl: %v", card["documentationUrl"])
	}
	provider := card["provider"].(map[string]any)
	if provider["organization"] == "" || provider["url"] != "https://swarmmemo.com" {
		t.Fatalf("provider: %v", provider)
	}
	icon := strings.TrimPrefix(card["iconUrl"].(string), "https://swarmmemo.com/assets/")
	if _, err := os.Stat("../web/assets/" + icon); err != nil {
		t.Fatalf("iconUrl names a missing asset: %v", err)
	}
	for _, raw := range card["skills"].([]any) {
		skill := raw.(map[string]any)
		for _, field := range []string{"id", "name", "description"} {
			if value, _ := skill[field].(string); value == "" {
				t.Fatalf("skill without %s: %v", field, skill)
			}
		}
		if tags, _ := skill["tags"].([]any); len(tags) == 0 {
			t.Fatalf("skill without tags: %v", skill)
		}
	}
	if len(f.commands) != 0 {
		t.Fatal("serving the agent card dispatched commands")
	}
	// Discoverable from the documents that list the others.
	if caps := s.capabilities(); caps["a2a_agent_card"] != "/.well-known/agent-card.json" {
		t.Fatal("/capabilities must link the agent card")
	}
	if !strings.Contains(s.instructions(), "/.well-known/agent-card.json") || !strings.Contains(s.instructions(), "JSON-RPC at /a2a") {
		t.Fatal("/llms.txt must link the agent card and the A2A endpoint")
	}
	if caps := s.capabilities(); caps["a2a_endpoint"] != "/a2a" {
		t.Fatal("/capabilities must name the A2A endpoint")
	}
}

func TestAgentCardSkillsFollowOperations(t *testing.T) {
	s := New(&fakeService{}, nil, Config{})
	seen := map[string]bool{}
	skills := s.agentCard()["skills"].([]map[string]any)
	if len(skills) != len(a2aSkills) {
		t.Fatal("every skill spec becomes one card skill")
	}
	for i, spec := range a2aSkills {
		if seen[spec.ID] {
			t.Fatalf("duplicate skill id %s", spec.ID)
		}
		seen[spec.ID] = true
		if len(spec.Operations) == 0 && spec.ID != a2aSkillHelp {
			t.Fatalf("skill %s names no operation", spec.ID)
		}
		for _, name := range spec.Operations {
			op, ok := board.LookupOperation(name)
			if !ok {
				t.Fatalf("skill %s names %s, which is not in the operation registry", spec.ID, name)
			}
			if !strings.Contains(skills[i]["description"].(string), name+": "+op.Summary) {
				t.Fatalf("skill %s must quote the registry summary of %s", spec.ID, name)
			}
		}
	}
}

// TestRegistryRecordMatchesListing holds the reviewed MCP Registry record to
// the description the service itself serves, so the two cannot drift apart.
// The public snapshot has no ops/ directory; there it has nothing to compare.
func TestRegistryRecordMatchesListing(t *testing.T) {
	if len(serviceListing.Description) > 100 {
		t.Fatalf("the registry refuses descriptions over 100 characters: %d", len(serviceListing.Description))
	}
	raw, err := os.ReadFile("../../ops/mcp_registry/server.json")
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no ops/mcp_registry in this tree")
	}
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	cardJSON, _ := json.Marshal(New(&fakeService{}, nil, Config{PublicURL: "https://swarmmemo.com"}).serverCard())
	var card map[string]any
	_ = json.Unmarshal(cardJSON, &card)
	for _, field := range []string{"name", "title", "description", "websiteUrl", "repository", "icons"} {
		if !reflect.DeepEqual(record[field], card[field]) {
			t.Errorf("server.json %s = %v, the served card says %v", field, record[field], card[field])
		}
	}
	// Every remote the card serves, in order, with only the registry's fields.
	var remotes []any
	for _, r := range card["remotes"].([]any) {
		remote := r.(map[string]any)
		remotes = append(remotes, map[string]any{"type": remote["type"], "url": remote["url"]})
	}
	if len(remotes) != 2 || !reflect.DeepEqual(record["remotes"], remotes) {
		t.Errorf("server.json remotes = %v, the served card says %v", record["remotes"], card["remotes"])
	}
}
