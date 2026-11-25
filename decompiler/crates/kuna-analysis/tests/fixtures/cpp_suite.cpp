// Comprehensive MSVC x64 C++ ground-truth fixture for Phases 3 (PDB), 4 (MSVC Classes), and 5 (Outlining)
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

struct Vec3 {
    float x;
    float y;
    float z;
};

enum class EntityKind : uint32_t {
    Unknown = 0,
    Player = 1,
    Vehicle = 2,
    Prop = 3,
};

struct BitFlags {
    uint32_t active : 1;
    uint32_t visible : 1;
    uint32_t team : 4;
    uint32_t lod : 3;
    uint32_t reserved : 23;
};

// Base 1: primary polymorphic interface
class Entity {
public:
    uint64_t entity_id;
    Vec3 position;
    EntityKind kind;
    BitFlags flags;

    __declspec(noinline) Entity(uint64_t id, EntityKind k)
        : entity_id(id), position{1.0f, 2.0f, 3.0f}, kind(k) {
        flags.active = 1;
        flags.visible = 1;
        flags.team = 2;
        flags.lod = 0;
        flags.reserved = 0;
    }

    __declspec(noinline) virtual ~Entity() {
        entity_id = 0;
    }

    __declspec(noinline) virtual float compute_score(float scale) const {
        return (position.x + position.y + position.z) * scale;
    }

    __declspec(noinline) virtual void tick(float dt) {
        position.x += dt;
    }

    __declspec(noinline) uint64_t get_id() const {
        return entity_id;
    }
};

// Base 2: secondary polymorphic interface (forces secondary vftable + adjustor thunks in MI!)
class Serializable {
public:
    uint32_t schema_version;
    uint32_t dirty_mask;

    __declspec(noinline) Serializable(uint32_t ver) : schema_version(ver), dirty_mask(0) {}
    __declspec(noinline) virtual ~Serializable() { dirty_mask = 0xFFFFFFFFu; }
    __declspec(noinline) virtual size_t serialize(uint8_t* dst, size_t cap) const {
        if (cap < 4) return 0;
        std::memcpy(dst, &schema_version, 4);
        return 4;
    }
    __declspec(noinline) virtual uint32_t checksum() const {
        return schema_version ^ dirty_mask;
    }
};

// Derived with multiple inheritance (Entity at +0, Serializable at non-zero offset!)
class Actor : public Entity, public Serializable {
public:
    int32_t health;
    int32_t armor;
    std::string label;
    std::vector<uint32_t> inventory;

    __declspec(noinline) Actor(uint64_t id, const char* name, int32_t hp)
        : Entity(id, EntityKind::Player), Serializable(7), health(hp), armor(50), label(name) {
        inventory.push_back(100);
        inventory.push_back(200);
    }

    __declspec(noinline) ~Actor() override {
        health = 0;
        armor = 0;
    }

    __declspec(noinline) float compute_score(float scale) const override {
        return Entity::compute_score(scale) + static_cast<float>(health + armor);
    }

    __declspec(noinline) void tick(float dt) override {
        Entity::tick(dt);
        if (health > 0) {
            armor += static_cast<int32_t>(dt);
        }
    }

    // Overrides Serializable -> MSVC emits a `this`-adjustor thunk in Actor::vftable_for_Serializable!
    __declspec(noinline) size_t serialize(uint8_t* dst, size_t cap) const override {
        if (cap < 16) return 0;
        std::memcpy(dst, &entity_id, 8);
        std::memcpy(dst + 8, &health, 4);
        std::memcpy(dst + 12, &armor, 4);
        return 16;
    }

    __declspec(noinline) uint32_t checksum() const override {
        return static_cast<uint32_t>(entity_id) ^ static_cast<uint32_t>(health) ^ schema_version;
    }
};

// Virtual base / diamond hierarchy test
class Tracked {
public:
    uint64_t trace_token;
    __declspec(noinline) Tracked(uint64_t tok) : trace_token(tok) {}
    __declspec(noinline) virtual ~Tracked() { trace_token = 0; }
    __declspec(noinline) virtual uint64_t token() const { return trace_token; }
};

class LeftBranch : virtual public Tracked {
public:
    uint32_t left_tag;
    __declspec(noinline) LeftBranch(uint64_t tok, uint32_t t) : Tracked(tok), left_tag(t) {}
    __declspec(noinline) uint64_t token() const override { return trace_token ^ left_tag; }
};

class RightBranch : virtual public Tracked {
public:
    uint32_t right_tag;
    __declspec(noinline) RightBranch(uint64_t tok, uint32_t t) : Tracked(tok), right_tag(t) {}
    __declspec(noinline) uint64_t token() const override { return trace_token + right_tag; }
};

class DiamondNode : public LeftBranch, public RightBranch {
public:
    uint32_t diamond_value;
    __declspec(noinline) DiamondNode(uint64_t tok, uint32_t l, uint32_t r, uint32_t d)
        : Tracked(tok), LeftBranch(tok, l), RightBranch(tok, r), diamond_value(d) {}
    __declspec(noinline) uint64_t token() const override {
        return trace_token ^ left_tag ^ right_tag ^ diamond_value;
    }
};

// Force-inlined proprietary helper repeated across many callers (tests Phase 5 outlining!)
__forceinline uint32_t mix_hash_helper(const uint8_t* data, size_t len, uint32_t seed) {
    uint32_t h = seed ^ 0x811c9dc5u;
    for (size_t i = 0; i < len; ++i) {
        h ^= data[i];
        h *= 0x01000193u;
        if ((h & 0xf) == 0) {
            h ^= (h >> 13);
            h += 0x9e3779b9u;
        }
    }
    return h ^ (h >> 16);
}

// Out-of-line twin of mix_hash_helper (tests twin matching too!)
__declspec(noinline) uint32_t standalone_mix_hash(const uint8_t* data, size_t len, uint32_t seed) {
    return mix_hash_helper(data, len, seed);
}

// Multiple callers that inline both mix_hash_helper and std::string operations
#define MAKE_CALLER(N, SEED) \
__declspec(noinline) uint32_t heavy_caller_##N(const uint8_t* buf, size_t n, Actor* actor, std::string& out) { \
    uint32_t h1 = mix_hash_helper(buf, n, SEED); \
    out.assign(reinterpret_cast<const char*>(buf), n > 32 ? 32 : n); \
    out.append("_tag"); \
    uint32_t h2 = mix_hash_helper(reinterpret_cast<const uint8_t*>(out.data()), out.size(), h1 ^ actor->checksum()); \
    return h2 + static_cast<uint32_t>(actor->compute_score(1.5f)); \
}

MAKE_CALLER(1, 0x1111u)
MAKE_CALLER(2, 0x2222u)
MAKE_CALLER(3, 0x3333u)
MAKE_CALLER(4, 0x4444u)
MAKE_CALLER(5, 0x5555u)
MAKE_CALLER(6, 0x6666u)

// Global typed objects (tests Phase 3 PDB globals!)
static EntityKind g_default_kind = EntityKind::Vehicle;
Vec3 g_world_origin = {10.0f, 20.0f, 30.0f};

__declspec(noinline) int run_polymorphic(Entity* e, Serializable* s, Tracked* t) {
    uint8_t buf[32];
    e->tick(2.5f);
    float sc = e->compute_score(2.0f);
    size_t n = s->serialize(buf, sizeof(buf));
    uint32_t c = s->checksum();
    uint64_t tok = t->token();
    return static_cast<int>(sc) + static_cast<int>(n) + static_cast<int>(c ^ tok);
}

int main(int argc, char** argv) {
    Actor* a = new Actor(static_cast<uint64_t>(argc) + 42, "hero", 100);
    DiamondNode* d = new DiamondNode(0x12345678ULL, 3, 5, 9);
    int res = run_polymorphic(a, a, d);
    std::string tmp;
    uint8_t payload[24] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24};
    uint32_t acc = standalone_mix_hash(payload, sizeof(payload), static_cast<uint32_t>(res));
    acc ^= heavy_caller_1(payload, sizeof(payload), a, tmp);
    acc ^= heavy_caller_2(payload, sizeof(payload), a, tmp);
    acc ^= heavy_caller_3(payload, sizeof(payload), a, tmp);
    acc ^= heavy_caller_4(payload, sizeof(payload), a, tmp);
    acc ^= heavy_caller_5(payload, sizeof(payload), a, tmp);
    acc ^= heavy_caller_6(payload, sizeof(payload), a, tmp);
    acc += static_cast<uint32_t>(g_default_kind) + static_cast<uint32_t>(g_world_origin.x);
    delete a;
    delete d;
    std::printf("%u\n", acc);
    return static_cast<int>(acc & 0x7f);
}
