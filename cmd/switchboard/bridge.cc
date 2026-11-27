#include "bridge.h"

#include <algorithm>
#include <array>
#include <memory>
#include <sstream>
#include <cstdio>
#include <string>
#include <vector>

#include "imtui/imtui.h"
#include "imgui/imgui_internal.h"

namespace {
std::unique_ptr<ImTui::TScreen> screen;
bool reset_layout = true;
int selected_call = 0;
const ImColor fore_blue(153, 213, 251);
const ImColor fore_red(234, 51, 35);
const ImColor fore_yellow(255, 255, 151);
const ImColor fore_green(117, 251, 76);
const ImColor minimizer_idle(95, 95, 132);
const ImColor minimizer_hover(115, 173, 249);
std::string wide_sample;
struct LiveCall {
    std::string id, subject, status, floor, participants, route, progress;
};
std::vector<LiveCall> live_calls;
std::string live_line, live_error, transcript_id, live_transcript, live_overview, live_topology;
// The row cache belongs to live_transcript and is rebuilt on text or width changes.
int transcript_width = 0;
struct TranscriptRow {
    std::string text;
    char ink;
};
std::vector<TranscriptRow> transcript_rows;
std::string transcript_inks, overview_colors, topology_colors;

ImVec4 foreground(char ink) {
    switch (ink) {
        case 'b': return fore_blue;
        case 'g': return fore_green;
        case 'y': return fore_yellow;
        case 'r': return fore_red;
        default: return ImGui::GetStyleColorVec4(ImGuiCol_Text);
    }
}

void status_lines(const std::string &text, const std::string &inks, bool wrap = false) {
    size_t start = 0;
    for (size_t line = 0; start < text.size(); ++line) {
        const size_t end = text.find('\n', start);
        ImGui::PushStyleColor(ImGuiCol_Text, foreground(line < inks.size() ? inks[line] : ' '));
        if (wrap)
            ImGui::PushTextWrapPos(ImGui::GetCursorPosX() +
                                   std::max(1.f, ImGui::GetContentRegionAvail().x - 2));
        ImGui::TextUnformatted(text.data() + start, text.data() + std::min(end, text.size()));
        if (wrap) ImGui::PopTextWrapPos();
        ImGui::PopStyleColor();
        if (end == std::string::npos) break;
        start = end + 1;
    }
}
bool live = false;
bool follow = true;
bool transcript_changed = false;
bool show_topology = false;

const char *const calls[] = {
    "Reverse idle wake",
    "Idle wake trial",
    "Terminal check",
};

const char *const transcript[][4] = {
    {"codex-peer", "Repeat the challenge words.", "codex", "copper lantern finch"},
    {"codex", "Repeat the challenge words.", "codex-peer", "silver orchard nine"},
    {"operator", "Příliš žluťoučký kůň", "codex-peer", nullptr},
};

struct PaneLayout {
    ImVec2 position, size;
};
PaneLayout calls_layout, transcript_layout, status_layout;

void place_pane(PaneLayout &previous, ImVec2 position, ImVec2 size, bool toggle, const char *name) {
    const auto *window = ImGui::FindWindowByName(name);
    const auto same = [](ImVec2 a, ImVec2 b) { return a.x == b.x && a.y == b.y; };
    // Fit a default pane to a resized terminal while preserving manual moves and resizes.
    const bool refit_pos = window && !same(position, previous.position) && same(window->Pos, previous.position);
    const bool refit_size = window && !same(size, previous.size) && same(window->SizeFull, previous.size);
    ImGui::SetNextWindowPos(position, reset_layout || refit_pos ? ImGuiCond_Always : ImGuiCond_FirstUseEver);
    ImGui::SetNextWindowSize(size, reset_layout || refit_size ? ImGuiCond_Always : ImGuiCond_FirstUseEver);
    previous = {position, size};
    if (toggle) {
        if (window)
            ImGui::SetNextWindowCollapsed(!window->Collapsed);
    } else if (reset_layout) {
        ImGui::SetNextWindowCollapsed(false);
    }
}

// Add the frame to the pane's own draw list so overlap and menus follow
// ImGui's window order. The native title still handles mouse input.
void pane_frame(const char *title, bool expanded, bool closable = false) {
    const auto pos = ImGui::GetWindowPos();
    const auto size = ImGui::GetWindowSize();
    const int width = static_cast<int>(size.x);
    const int height = static_cast<int>(size.y);
    auto *draw = ImGui::GetWindowDrawList();
    const auto color = ImGui::GetColorU32(ImGuiCol_Text);
    const auto background = ImGui::GetColorU32(ImGuiCol_WindowBg);
    draw->PushClipRect(pos, ImVec2(pos.x + width, pos.y + height), false);
    // The text renderer places glyph centers one column inside the
    // rectangle rasterizer's origin. Start the fill at that same column.
    draw->AddRectFilled(ImVec2(pos.x + 1, pos.y),
                       ImVec2(pos.x + width - 1, pos.y + height - 1), background);
    const auto glyph = [&](int x, int y, const char *text) {
        draw->AddText(ImVec2(pos.x + x, pos.y + y), color, text);
    };
    glyph(0, 0, expanded ? "╔" : "╶");
    glyph(1, 0, expanded ? "═╡" : "─┤");
    const ImGuiID collapse = ImGui::GetCurrentWindow()->GetID("#COLLAPSE");
    const auto &g = *ImGui::GetCurrentContext();
    const bool hovered = g.HoveredId == collapse;
    ImU32 button_color = minimizer_idle;
    if (hovered)
        button_color = g.ActiveId == collapse ? ImGui::GetColorU32(ImGuiCol_ButtonActive)
                                              : static_cast<ImU32>(minimizer_hover);
    draw->AddText(ImVec2(pos.x + 3, pos.y), button_color, "█");
    std::string top = expanded ? "╞══╡" : "├──┤";
    const auto visible_title = std::string(title).substr(0, std::max(0, width - (closable ? 17 : 11)));
    top += visible_title;
    top += expanded ? " ╞" : " ├";
    for (int x = 10 + static_cast<int>(visible_title.size()); x < width - 2; ++x)
        top += expanded ? "═" : "─";
    top += expanded ? "╗" : "╴";
    glyph(4, 0, top.c_str());
    if (closable) {
        glyph(width - 5, 0, expanded ? "╡ ╞" : "┤ ├");
        const ImGuiID id = ImGui::GetCurrentWindow()->GetID("#CLOSE");
        const ImU32 ink = g.ActiveId == id ? ImGui::GetColorU32(ImGuiCol_ButtonActive) : ImU32(fore_red);
        draw->AddText(ImVec2(pos.x + width - 4, pos.y), ink, g.HoveredId == id ? "×" : "●");
    }
    if (expanded) {
        for (int y = 1; y < height - 1; ++y) {
            glyph(0, y, "║");
            glyph(width - 2, y, "║");
        }
        std::string bottom = "╚";
        for (int x = 1; x < width - 2; ++x)
            bottom += "═";
        bottom += "╝";
        glyph(0, height - 1, bottom.c_str());
    }
    draw->PopClipRect();
}

bool begin_pane(const char *name, ImGuiWindowFlags flags = 0, bool *open = nullptr) {
    const ImVec4 transparent(0, 0, 0, 0);
    ImGui::PushStyleColor(ImGuiCol_Text, transparent);
    ImGui::PushStyleColor(ImGuiCol_TitleBg, transparent);
    ImGui::PushStyleColor(ImGuiCol_TitleBgActive, transparent);
    ImGui::PushStyleColor(ImGuiCol_TitleBgCollapsed, transparent);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(2, 0));
    const bool expanded = ImGui::Begin(name, open, ImGuiWindowFlags_NoBackground | flags);
    ImGui::PopStyleVar();
    ImGui::PopStyleColor(4);
    return expanded;
}

void draw_transcript() {
    // Leave room for the text backend’s one-cell glyph offset at the right clip edge.
    const int width = std::max(1, static_cast<int>(ImGui::GetContentRegionAvail().x) - 2);
    if (width != transcript_width) {
        transcript_rows.clear();
        const char *start = live_transcript.data();
        const char *end = start + live_transcript.size();
        for (size_t line = 0;; ++line) {
            const char ink = line < transcript_inks.size() ? transcript_inks[line] : ' ';
            const char *eol = std::find(start, end, '\n');
            if (start == eol) {
                std::string text;
                if (ink == 'd')
                    for (int col = 0; col < width; ++col)
                        text += "┄";
                transcript_rows.push_back({text, ink == 'd' ? 'b' : ink});
            }
            while (start < eol) {
                const char *next = ImGui::GetFont()->CalcWordWrapPositionA(1.0f, start, eol, width);
                if (next == start) {
                    unsigned int codepoint;
                    next += ImTextCharFromUtf8(&codepoint, start, eol);
                }
                transcript_rows.push_back({std::string(start, next), ink});
                start = next;
                while (start < eol && *start == ' ')
                    ++start;
            }
            if (eol == end)
                break;
            start = eol + 1;
        }
        transcript_width = width;
        transcript_changed = true;
    }

    // Keep the full scroll range without submitting offscreen transcript glyphs.
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(transcript_rows.size()), ImGui::GetTextLineHeightWithSpacing());
    while (clipper.Step()) {
        for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
            const auto &item = transcript_rows[row];
            ImGui::PushStyleColor(ImGuiCol_Text, foreground(item.ink));
            ImGui::TextUnformatted(item.text.c_str());
            ImGui::PopStyleColor();
        }
    }
}

std::string call_state(const LiveCall &call) {
    std::string state = call.progress.empty() ? call.status : call.progress;
    if (!call.floor.empty()) state += " · Floor: " + call.floor;
    return state;
}

ImVec4 state_color(const LiveCall &call) {
    if (call.status == "open") return fore_green;
    if (call.status == "deferred" || call.status == "stale") return fore_yellow;
    return fore_blue;
}

// ImTUI's custom frame occupies actual terminal cells inside the native window.
void clip_pane_content() {
    const auto pos = ImGui::GetWindowPos(), size = ImGui::GetWindowSize();
    ImGui::PushClipRect(ImVec2(pos.x + 2, pos.y + 1),
                        ImVec2(pos.x + size.x - 1, pos.y + size.y - 1), true);
}

bool begin_conversation() {
    const auto pos = ImGui::GetWindowPos(), size = ImGui::GetWindowSize();
    const auto cursor = ImGui::GetCursorScreenPos();
    const float height = std::max(1.0f, pos.y + size.y - 1 - cursor.y);
    // The zero-width child fills the remaining space from its new origin.
    ImGui::SetCursorScreenPos(ImVec2(cursor.x + 1, cursor.y));
    return ImGui::BeginChild("##messages", ImVec2(0, height), false, ImGuiWindowFlags_NoBackground);
}

void divider() {
    const int width = std::max(0, static_cast<int>(ImGui::GetContentRegionAvail().x) - 2);
    std::string line;
    for (int column = 0; column < width; ++column)
        line += "─";
    ImGui::TextColored(fore_blue, "%s", line.c_str());
}

struct Field {
    std::string label;
    bool checkbox, checked = false;
    std::array<char, 4096> value{};
    Field(const char *name, bool box) : label(name), checkbox(box) {}
};
struct Action {
    std::string group, label;
    std::vector<Field> fields;
};
std::vector<Action> actions;
std::vector<std::string> known_lines, relay_lines, relay_labels;
enum View {
    Topology,
    Relays,
    Broadcasts,
    Roadmaps,
    Configuration,
    CreateLine,
    AddAgent,
    ManageLines,
    ManageAgents,
    Connect,
    ClientTools,
    Operator,
    Compose,
    Help,
    ViewCount
};
struct WindowSpec {
    const char *title;
    int width, height;
    const char *help;
};
const WindowSpec windows[] = {
    {"Line topology", 96, 32,
     "Read the tree from the line to each workstation and actor. A worktree identifies an agent by its "
     "checkout. A shared seat identifies it by provider configuration. A profile seat can start from "
     "several checkouts. Local registrations appear alongside the verified relay roster. Remote machines "
     "keep their checkout paths private."},
    {"Relays", 108, 38,
     "A relay connects agents on separate machines. Each local line can attach to one enrolled client "
     "directory. Select a listed line to observe its checkpoint and connection. Connect to a Relay walks "
     "through joining. Detach returns the local line to local routing and keeps its credential files. "
     "Revoke the credential separately to withdraw membership."},
    {"Broadcasts", 84, 32,
     "Read announcements, briefings and regroups for the selected line. Compose opens a separate draft. "
     "Choose recipients, review the message and apply to send."},
    {"Roadmaps", 142, 36,
     "Each agent posts an arc of work. Read across its stations to find its current marker. The legend "
     "describes the stations and any detours. Resize the window to change the space available to the map."},
    {"Configuration", 74, 34,
     "Manage local lines and agents with the buttons above the settings. Use Diagnostics for Doctor and "
     "Resources to inspect or apply the shared resource configuration. Review shows the settings before "
     "Apply runs the operation."},
    {"Create a Line", 58, 17,
     "A line is a named meeting place for agents. Choose a short lowercase name. Review and apply to "
     "create and select it. Then choose Add Agent to install the first provider. Other local checkouts can "
     "join by using the same name."},
    {"Add Agent", 80, 32,
     "Choose the runtime and the name other agents should call. Worktree installs in an existing checkout. "
     "Leave the path empty for this checkout. New worktree creates a Git worktree at the path you enter, "
     "using Git's normal branch naming. Shared seat lets Codex or Antigravity share a checkout. A Codex "
     "profile can launch from any checkout. After installation, follow the provider instructions in the "
     "result and run Doctor."},
    {"Manage Lines", 76, 28,
     "Select a local line to view its agents, calls and attachment. Create a Line makes a new named line. "
     "Manage Agents works on the line currently shown as active."},
    {"Manage Agents", 92, 34,
     "Inspect the local registrations and relay actor mappings for the active line. Add Agent installs "
     "runtime configuration. Remove agent uninstalls the named local identity. Manage remote actors and "
     "credential revocation from Relays."},
    {"Connect to a Relay", 88, 36,
     "1. Obtain the signed descriptor and compare its fingerprint with the operator over a trusted "
     "channel. Verify relay connection checks the origin.\n\n2. Create a workstation request in a private "
     "client directory. Send the request and compare the signing and encryption fingerprints with the "
     "operator.\n\n3. Prove workstation keys using the returned challenge and independently verified "
     "operator key. Return the proof. The operator enrolls the credential and activates the reader "
     "epoch.\n\n4. Activate this workstation, declare its actor, then attach a local line. Open Relays to "
     "see the last verified checkpoint. An existing enrolled client can go straight to Attach local line."},
    {"Relay client", 92, 38,
     "Use Client tools to inspect or sync a workstation, manage its actors and read or publish registers. "
     "Relay calls and broadcasts use the actor and credential you specify. Review the identity, recipients "
     "and content before applying."},
    {"Relay operator", 92, 38,
     "On the host, generate a certificate, provision the signed line and serve it. Monitor the local admin "
     "socket for admission counters and clock state. Enroll workstation checks key fingerprints and issues "
     "a challenge. Line administration manages offline root and operator authority. Use SSH for host-local "
     "operations."},
    {"Compose broadcast", 78, 30,
     "Choose the broadcast kind and recipients. Enter the message across as many lines as you need. Review "
     "shows the full draft. Apply sends it with the selected attribution. For a relay broadcast use an "
     "authorized operator key."},
    {"Help", 76, 24, ""}};
struct WindowState {
    bool open = false, focus = false, reviewing = false;
    int action = -1, result_state = 0;
    std::string result;
    PaneLayout layout{};
};
WindowState desk[ViewCount];
int submitted = -1, last_action = -1, roadmap_width = 65;
View result_owner = Configuration, help_topic = Topology;
bool busy = false;
std::string extra_text[4], extra_inks[4];
void present(View v) {
    desk[v].open = true;
    desk[v].focus = true;
}
bool section(View v, const std::string &group) {
    switch (v) {
    case Configuration:
        return group == "Diagnostics" || group == "Resources" || group == "Calls";
    case Connect:
        return group == "Connect to relay";
    case ClientTools:
        return group == "Client tools" || group == "Relay calls" || group == "Relay broadcasts";
    case Operator:
        return group == "Enroll workstation" || group == "Host a line" || group == "Line administration";
    case Compose:
        return group == "Broadcasts";
    default:
        return group == windows[v].title;
    }
}
std::string attached_dir;
void choose_action(View v, int index) {
    auto &w = desk[v];
    if (busy && v == result_owner)
        return;
    w.action = index;
    w.reviewing = false;
    w.result.clear();
    w.result_state = 0;
    for (auto &f : actions[index].fields) {
        if (f.label == "Client directory" && actions[index].label != "Create workstation request" &&
            !attached_dir.empty() && !f.value[0])
            std::snprintf(f.value.data(), f.value.size(), "%s", attached_dir.c_str());
        if (f.label == "Local line")
            std::snprintf(f.value.data(), f.value.size(), "%s", live_line.c_str());
    }
}
void launch_form(View v, const char *label) {
    for (int i = 0; i < (int)actions.size(); ++i)
        if (actions[i].label == label && section(v, actions[i].group)) {
            choose_action(v, i);
            break;
        }
    present(v);
}
const char *choice_label(const Field &f, const char *value) {
    if (f.label == "Provider" || f.label == "Runtime") {
        const std::string key = value;
        if (key == "agy")
            return "Antigravity (Gemini)";
        if (key == "codex")
            return "Codex";
        if (key == "claude")
            return "Claude Code";
        if (key == "claude-channels")
            return "Claude Code · Channels";
        if (key == "claude-rewake")
            return "Claude Code · rewake";
    }
    return value;
}
void choice(Field &f, const std::vector<std::string> &items) {
    if (items.empty())
        return;
    if (std::find(items.begin(), items.end(), std::string(f.value.data())) == items.end())
        std::snprintf(f.value.data(), f.value.size(), "%s", items.front().c_str());
    if (ImGui::BeginCombo("##choice", choice_label(f, f.value.data()))) {
        for (const auto &value : items)
            if (ImGui::Selectable(choice_label(f, value.c_str()), value == f.value.data()))
                std::snprintf(f.value.data(), f.value.size(), "%s", value.c_str());
        ImGui::EndCombo();
    }
}
void config_form(View v) {
    auto &w = desk[v];
    std::vector<int> options;
    std::vector<int> groups;
    for (int i = 0; i < (int)actions.size(); ++i)
        if (section(v, actions[i].group)) {
            options.push_back(i);
            if (groups.empty() || actions[groups.back()].group != actions[i].group)
                groups.push_back(i);
        }
    if (options.empty())
        return;
    if (w.action < 0)
        choose_action(v, options.front());
    const int &active_form = w.action;
    bool &reviewing = w.reviewing;
    auto &result = w.result;
    auto &result_state = w.result_state;
    if (result_state != 1 && !reviewing) {
        if (groups.size() > 1 && ImGui::BeginCombo("Section", actions[active_form].group.c_str())) {
            for (int i : groups)
                if (ImGui::Selectable(actions[i].group.c_str()))
                    choose_action(v, i);
            ImGui::EndCombo();
        }
        if (options.size() > 1 && ImGui::BeginCombo("Action", actions[active_form].label.c_str())) {
            for (int i : options)
                if (actions[i].group == actions[active_form].group &&
                    ImGui::Selectable(actions[i].label.c_str(), active_form == i))
                    choose_action(v, i);
            ImGui::EndCombo();
        }
    }
    auto &action = actions[active_form];
    if ((reviewing || options.size() == 1) && action.label != windows[v].title) {
        ImGui::TextColored(fore_yellow, "%s", action.label.c_str());
        divider();
    }
    if (v == CreateLine)
        ImGui::TextWrapped("Choose a name with lowercase letters, digits and hyphens.");
    if (v == AddAgent)
        ImGui::TextWrapped("Install the agent in a checkout, a shared seat or a profile.");
    if (action.label == "Detach local line")
        ImGui::TextWrapped("Calls on this local line will use local routing. The enrolled workstation "
                           "keeps its credential.");
    if (action.label == "Record measurement")
        ImGui::TextWrapped("Record the proposed measurement command for the participants to review.");
    if (action.label == "Create workstation request")
        ImGui::TextWrapped("Compare the descriptor fingerprint through a trusted channel. Send the request "
                           "file and verify both workstation fingerprints with the operator.");
    if (action.label == "Inspect signed request")
        ImGui::TextWrapped("Check the signed line, namespace, actor limit and reader grant. "
                           "Use the resulting request digest when issuing the challenge.");
    if (action.label == "Issue challenge")
        ImGui::TextWrapped("Compare both fingerprints with the workstation owner. Return the challenge file. "
                           "Keep the secret file on this workstation.");
    if (action.label == "Prove workstation keys")
        ImGui::TextWrapped(
            "Verify the operator public key independently. Return the proof file to the operator.");
    if (action.label == "Serve in this terminal")
        ImGui::TextWrapped("Apply closes this board and runs the relay in the foreground. Ctrl-C stops the relay.");
    ImGui::PushID(active_form);
    for (auto &field : action.fields) {
        if (v == AddAgent && ((field.label == "Checkout-local Claude settings" &&
                               std::string(action.fields[1].value.data()).find("claude") != 0) ||
                              (field.label.find("Worktree path") == 0 &&
                               std::string(action.fields[3].value.data()) == "Codex profile") ||
                              (field.label.find("Profile name") == 0 &&
                               std::string(action.fields[3].value.data()) != "Codex profile")))
            continue;
        ImGui::PushID(field.label.c_str());
        if (reviewing || result_state == 1) {
            ImGui::TextWrapped("%s: %s", field.label.c_str(),
                               field.checkbox ? (field.checked ? "yes" : "no") : field.value.data());
        } else if (field.checkbox) {
            ImGui::Checkbox(field.label.c_str(), &field.checked);
        } else {
            const char *label = field.label.c_str();
            if (v == AddAgent && field.label.find("Profile name") == 0)
                label = "Profile name";
            if (v == AddAgent && field.label.find("Worktree path") == 0 &&
                std::string(action.fields[3].value.data()) == "New worktree")
                label = "New worktree path";
            ImGui::TextColored(fore_blue, "%s", label);
            ImGui::SetNextItemWidth(std::max(8.0f, ImGui::GetContentRegionAvail().x - 3));
            if (field.label == "Provider" || field.label == "Runtime")
                choice(field, {"claude", "claude-channels", "claude-rewake", "codex", "agy"});
            else if (field.label == "Default addressing (true/false)")
                choice(field, {"true", "false"});
            else if (field.label == "Kind" && action.group == "Broadcasts")
                choice(field, {"briefing", "regroup", "announcement"});
            else if (field.label == "Attachment") {
                std::vector<std::string> modes = {"Worktree", "New worktree"};
                const std::string provider = action.fields[1].value.data();
                if (provider == "codex" || provider == "agy")
                    modes.push_back("Shared seat");
                if (provider == "codex")
                    modes.push_back("Codex profile");
                choice(field, modes);
                const std::string mode = field.value.data();
                ImGui::TextWrapped(
                    "%s", mode == "Shared seat" ? "Shares an existing checkout under a separate agent name."
                          : mode == "Codex profile" ? "Launch from any checkout with codex -p PROFILE."
                          : mode == "New worktree"
                              ? "Create a Git worktree at a new path, then install the agent there."
                              : "Use this checkout or enter an existing worktree path.");
            } else if (field.label == "Message" || field.label == "Resolution")
                ImGui::InputTextMultiline("##value", field.value.data(), field.value.size(),
                                          ImVec2(std::max(8.f, ImGui::GetContentRegionAvail().x - 3), 4));
            else if (field.label == "Local line" && !known_lines.empty())
                choice(field, known_lines);
            else
                ImGui::InputText("##value", field.value.data(), field.value.size());
        }
        ImGui::PopID();
    }
    ImGui::PopID();
    if (v == AddAgent && !reviewing && result_state != 1) {
        const std::string provider = action.fields[1].value.data();
        std::string hint = provider.find("claude") == 0 ? "claude" : provider;
        if (provider == "claude-channels")
            hint = "claude --dangerously-load-development-channels server:yip";
        if (std::string(action.fields[3].value.data()) == "Codex profile")
            hint +=
                " -p " + std::string(action.fields[5].value[0] ? action.fields[5].value.data() : "PROFILE");
        ImGui::TextWrapped("Launch: %s", hint.c_str());
    }
    if (busy && result_owner != v)
        ImGui::TextDisabled("Another operation is running");
    else if (result_state != 1) {
        if (reviewing) {
            if (ImGui::Button("Apply") && !busy) {
                last_action = active_form;
                result_owner = v;
                submitted = active_form;
                reviewing = false;
            }
            ImGui::SameLine();
            if (ImGui::Button("Back"))
                reviewing = false;
        } else if (ImGui::Button("Review"))
            reviewing = true;
    }
    if (!result.empty()) {
        divider();
        ImGui::PushStyleColor(ImGuiCol_Text, static_cast<ImVec4>(result_state == 2   ? fore_red
                                                                 : result_state == 1 ? fore_blue
                                                                                     : fore_green));
        std::istringstream output(result);
        for (std::string line; std::getline(output, line);) {
            if (line.empty())
                ImGui::Dummy(ImVec2(0, 1));
            else
                ImGui::TextWrapped("%s", line.c_str());
        }
        ImGui::PopStyleColor();
    }
}
// Wrap toolbars by available cells, leaving their right gutter clear.
void toolbar(const std::vector<std::pair<const char *, View>> &items) {
    bool first = true;
    for (const auto &item : items) {
        const float end = ImGui::GetItemRectMax().x;
        if (!first && end + ImGui::CalcTextSize(item.first).x + 5 <
                          ImGui::GetWindowPos().x + ImGui::GetWindowContentRegionMax().x)
            ImGui::SameLine();
        if (ImGui::Button(item.first))
            present(item.second);
        first = false;
    }
}
void line_picker(View owner, const std::vector<std::string> &lines) {
    for (size_t n = 0; n < lines.size(); ++n) {
        const auto &line = lines[n];
        ImGui::PushID(line.c_str());
        if (ImGui::Selectable((line + "###line").c_str(), line == live_line) && line != live_line &&
            !busy && submitted < 0) {
            for (int i = 0; i < (int)actions.size(); ++i)
                if (actions[i].group == "Manage Lines") {
                    auto &f = actions[i].fields.front();
                    std::snprintf(f.value.data(), f.value.size(), "%s", line.c_str());
                    result_owner = owner;
                    submitted = last_action = i;
                    break;
                }
        }
        if (owner == Relays && n < relay_labels.size())
            status_lines(relay_labels[n], "b", true);
        ImGui::PopID();
    }
    auto &w = desk[owner];
    if (w.result_state == 2)
        ImGui::TextWrapped("%s", w.result.c_str());
}
void guide_section(const char *title, const char *body) {
    ImGui::Dummy(ImVec2(0, 1));
    ImGui::TextColored(fore_blue, "%s", title);
    ImGui::TextWrapped("%s", body);
}
void pane_body(View v) {
    if (v == Help) {
        ImGui::TextColored(fore_yellow, "%s", windows[help_topic].title);
        divider();
        const bool relay_help = help_topic == Connect || help_topic == Relays ||
                                help_topic == ClientTools || help_topic == Operator;
        if (relay_help) {
            guide_section("WHAT A RELAY DOES",
                          "A local line links agents on one machine. Attaching it to a relay lets enrolled "
                          "workstations exchange calls, broadcasts and roadmaps. Delivery into each agent "
                          "session still runs on its own machine.");
            guide_section("JOIN AN EXISTING LINE", windows[Connect].help);
            guide_section(
                "HOST A LINE",
                "On the relay machine, open Relays, then Relay operator. Use Host a line to generate the "
                "certificate. Use Line administration to create the root keys and sign a descriptor for "
                "the reachable origin. Provision and serve the line, initialize it, and authorize an "
                "operator. Give invitees the signed descriptor and verify its fingerprint separately. The "
                "LDR quickstart covers the complete ceremony and tunnel settings.");
            guide_section("CHECK OR REMOVE A CONNECTION",
                          "Select the attachment in Relays and read its authentication stage and last "
                          "verified checkpoint. Detach this line restores local routing. A workstation "
                          "credential remains enrolled until the operator revokes it.");
        } else {
            ImGui::TextWrapped("%s", windows[help_topic].help);
        }
        return;
    }
    if (v == Relays) {
        const bool columns =
            ImGui::GetContentRegionAvail().x >= 82 &&
            ImGui::BeginTable("##relay-stations", 2,
                              ImGuiTableFlags_BordersInnerV | ImGuiTableFlags_SizingStretchProp);
        if (columns) {
            ImGui::TableSetupColumn("Attachments", ImGuiTableColumnFlags_WidthStretch, 0.46f);
            ImGui::TableSetupColumn("Observation", ImGuiTableColumnFlags_WidthStretch, 0.54f);
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
        }
        ImGui::TextColored(fore_yellow, "Attached lines");
        if (relay_lines.empty())
            status_lines("Connect a workstation to bring a local line onto the relay.", " ", true);
        line_picker(v, relay_lines);
        divider();
        if (ImGui::Button("Connect to a Relay"))
            present(Connect);
        if (std::find(relay_lines.begin(), relay_lines.end(), live_line) != relay_lines.end() &&
            ImGui::Button("Detach this line"))
            launch_form(Connect, "Detach local line");
        if (columns)
            ImGui::TableNextColumn();
        else
            divider();
        ImGui::TextColored(fore_yellow, "Observing %s", live_line.c_str());
        status_lines(extra_text[Relays], extra_inks[Relays], true);
        if (columns)
            ImGui::EndTable();
        divider();
        toolbar({{"Client operations", ClientTools},
                 {"Relay operator", Operator},
                 {"Line topology", Topology}});
        return;
    }
    if (v == Topology)
        toolbar({{"Manage Agents", ManageAgents}, {"Relays", Relays}});
    if (v == Broadcasts)
        toolbar({{"Compose broadcast", Compose}});
    if (v <= Roadmaps) {
        if (v == Roadmaps)
            roadmap_width = std::max(20, int(ImGui::GetContentRegionAvail().x) - 4);
        if (extra_text[v].empty())
            ImGui::TextDisabled("%s", v == Broadcasts ? "No broadcasts" : "Awaiting line data");
        else
            status_lines(extra_text[v], extra_inks[v], true);
        return;
    }
    if (v == Configuration)
        toolbar({{"Manage Lines", ManageLines}, {"Manage Agents", ManageAgents}, {"Relays", Relays}});
    if (v == ManageLines) {
        ImGui::TextColored(fore_yellow, "Active line · %s", live_line.c_str());
        line_picker(v, known_lines);
        divider();
        toolbar({{"Create a Line", CreateLine}, {"Manage Agents", ManageAgents}, {"Relays", Relays}});
        return;
    }
    if (v == ManageAgents) {
        ImGui::TextColored(fore_yellow, "Agents on %s", live_line.c_str());
        if (ImGui::Button("Add Agent"))
            launch_form(AddAgent, "Add Agent");
        ImGui::SameLine();
        if (ImGui::Button("Relay actors"))
            launch_form(ClientTools, "List actors");
        status_lines(live_topology, topology_colors, true);
        divider();
        if (!ImGui::CollapsingHeader("Remove a local agent"))
            return;
    }
    config_form(v);
    if (v == CreateLine && !desk[v].result.empty() && desk[v].result_state == 0) {
        if (ImGui::Button("Add Agent"))
            launch_form(AddAgent, "Add Agent");
    }
}
void draw_views(int width, int height) {
    for (int index = 0; index < ViewCount; ++index) {
        View v = static_cast<View>(index);
        auto &w = desk[v];
        if (!w.open)
            continue;
        const auto &spec = windows[v];
        std::string name = std::string(" ") + spec.title;
        const int cols = std::min(spec.width, width - 2), rows = std::min(spec.height, height - 3);
        ImVec2 size(cols, rows), pos((width - cols - 1) / 2, 1 + (height - 1 - rows) / 2);
        place_pane(w.layout, pos, size, false, name.c_str());
        ImGui::SetNextWindowSizeConstraints(ImVec2(30, 6), ImVec2(width - 2, height - 2));
        if (w.focus) {
            ImGui::SetNextWindowFocus();
            ImGui::SetNextWindowCollapsed(false);
        }
        bool expanded = begin_pane(
            name.c_str(), ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse, &w.open);
        pane_frame(spec.title, expanded, true);
        if (expanded) {
            const auto origin = ImGui::GetWindowPos(), bounds = ImGui::GetWindowSize();
            ImGui::SetCursorPos(ImVec2(3, 2));
            const int footer = v == Help ? 1 : 3;
            const float inner_width = std::max(1.f, bounds.x - 7);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(1, 0));
            if (ImGui::BeginChild(
                    "##body", ImVec2(inner_width, std::max(1.f, bounds.y - 2 - footer)), false,
                    ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_AlwaysUseWindowPadding)) {
                ImGui::Indent(1);
                ImGui::PushTextWrapPos(inner_width - 2);
                if (w.focus && v == Help)
                    ImGui::SetScrollY(0);
                pane_body(v);
                ImGui::PopTextWrapPos();
                ImGui::Unindent(1);
            }
            ImGui::EndChild();
            ImGui::PopStyleVar();
            if (v != Help) {
                ImGui::SetCursorScreenPos(ImVec2(origin.x + bounds.x - 8, origin.y + bounds.y - 2));
                if (ImGui::Button(" ? ")) {
                    help_topic = v;
                    present(Help);
                }
                if (ImGui::IsItemHovered())
                    ImGui::SetTooltip("Help for %s", spec.title);
            }
        }
        w.focus = false;
        ImGui::End();
    }
}
} // namespace

extern "C" void board_action(const char *group, const char *label) {
    actions.push_back({group, label, {}});
}
extern "C" void board_field(const char *label, int box) {
    actions.back().fields.emplace_back(label, box != 0);
}
extern "C" int board_take_action() {
    int index = submitted;
    submitted = -1;
    return index;
}
extern "C" const char *board_value(int i) {
    const auto &f = actions[last_action].fields.at(i);
    return f.checkbox ? (f.checked ? "1" : "") : f.value.data();
}
extern "C" void board_result(const char *text, int state) {
    auto &w = desk[result_owner];
    w.result = text;
    w.result_state = state;
    busy = state == 1;
}
extern "C" void board_lines(const char *lines, const char *relays, const char *client, const char *labels) {
    attached_dir = client;
    auto split = [](const char *text, std::vector<std::string> &out) {
        out.clear();
        std::istringstream input(text);
        for (std::string line; std::getline(input, line);)
            if (!line.empty())
                out.push_back(line);
    };
    split(lines, known_lines);
    split(relays, relay_lines);
    split(labels, relay_labels);
}
extern "C" void board_extra(int i, const char *text, const char *inks) {
    extra_text[i] = text;
    extra_inks[i] = inks;
}
extern "C" void board_toggle_view(int i) {
    if (i < 0 || i >= ViewCount)
        return;
    if (desk[i].open)
        desk[i].open = false;
    else
        present(static_cast<View>(i));
}
extern "C" int board_views() {
    return (desk[Broadcasts].open ? 1 : 0) | (desk[Roadmaps].open ? 2 : 0) | (desk[Relays].open ? 4 : 0) |
           (std::min(256, roadmap_width) << 8);
}
extern "C" void board_help() {
    auto *window = ImGui::GetCurrentContext()->NavWindow;
    for (int i = 0; window && i < Help; ++i)
        if (desk[i].open &&
            window->RootWindow == ImGui::FindWindowByName((std::string(" ") + windows[i].title).c_str())) {
            help_topic = static_cast<View>(i);
            present(Help);
            return;
        }
    if (!desk[Help].open) {
        help_topic = ManageLines;
        present(Help);
    }
}
extern "C" int board_dismiss() {
    auto &g = *ImGui::GetCurrentContext();
    if (!g.NavWindow || g.OpenPopupStack.Size || g.ActiveId)
        return false;
    for (int i = 0; i < ViewCount; ++i)
        if (desk[i].open && g.NavWindow->RootWindow ==
                                ImGui::FindWindowByName((std::string(" ") + windows[i].title).c_str())) {
            desk[i].open = false;
            return true;
        }
    return false;
}
extern "C" int board_editing() {
    return ImGui::GetIO().WantTextInput;
}
extern "C" void board_key(int code, unsigned int rune) {
    auto &io = ImGui::GetIO();
    if (rune)
        io.AddInputCharacter(rune);
    if (code > 0 && code < 512) {
        io.KeysDown[code] = true;
        io.KeysDownDuration[code] = -1;
    }
}
extern "C" void board_init(const char *unicode_sample, uint32_t foreground[256]) {
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr;
    auto &io = ImGui::GetIO();
    io.KeyMap[ImGuiKey_Backspace] = 8;
    io.KeyMap[ImGuiKey_Enter] = 13;
    io.KeyMap[ImGuiKey_Escape] = 27;
    io.KeyMap[ImGuiKey_LeftArrow] = 256;
    io.KeyMap[ImGuiKey_RightArrow] = 257;
    io.KeyMap[ImGuiKey_Home] = 258;
    io.KeyMap[ImGuiKey_End] = 259;
    io.KeyMap[ImGuiKey_Delete] = 260;
    io.KeyMap[ImGuiKey_Tab] = 9;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.KeyMap[ImGuiKey_Space] = 32;
    io.KeyMap[ImGuiKey_UpArrow] = 261;
    io.KeyMap[ImGuiKey_DownArrow] = 262;
    io.KeyMap[ImGuiKey_PageUp] = 263;
    io.KeyMap[ImGuiKey_PageDown] = 264;
    actions.clear();
    for (auto &w : desk)
        w = WindowState{};
    submitted = last_action = -1;
    busy = false;
    ImTui_ImplText_Init();
    auto &style = ImGui::GetStyle();
    style.WindowMinSize = ImVec2(18, 5);
    style.FramePadding = ImVec2(1, 0);
    style.WindowPadding = ImVec2(3, 1);
    style.ItemSpacing = ImVec2(1, 0);
    style.WindowBorderSize = 0;
    style.Colors[ImGuiCol_WindowBg] = ImVec4(0.04f, 0.06f, 0.09f, 1.0f);
    style.Colors[ImGuiCol_Border] = fore_blue;
    style.Colors[ImGuiCol_TextDisabled] = fore_blue;
    style.Colors[ImGuiCol_TitleBg] = style.Colors[ImGuiCol_WindowBg];
    style.Colors[ImGuiCol_TitleBgActive] = style.Colors[ImGuiCol_WindowBg];
    style.Colors[ImGuiCol_TitleBgCollapsed] = style.Colors[ImGuiCol_WindowBg];
    style.Colors[ImGuiCol_MenuBarBg] = ImVec4(0.10f, 0.14f, 0.19f, 1.0f);
    // ImTUI stores an ANSI cube index per foreground. Recover these distinct
    // theme inks at the tcell boundary so a truecolor terminal gets exact RGB.
    for (ImU32 ink :
         {ImU32(fore_blue), ImU32(fore_red), ImU32(fore_yellow), ImU32(fore_green), ImU32(minimizer_idle),
          ImU32(minimizer_hover), ImGui::GetColorU32(ImGuiCol_ButtonActive)}) {
        const unsigned r = (ink >> IM_COL32_R_SHIFT) & 255;
        const unsigned g = (ink >> IM_COL32_G_SHIFT) & 255;
        const unsigned b = (ink >> IM_COL32_B_SHIFT) & 255;
        const auto cube = [](unsigned c) { return (c * 5 + 127) / 255; };
        foreground[16 + 36 * cube(r) + 6 * cube(g) + cube(b)] = (r << 16) | (g << 8) | b;
    }
    screen.reset(new ImTui::TScreen());
    reset_layout = true;
    selected_call = 0;
    wide_sample = unicode_sample;
    live = false;
    transcript_width = 0;
    follow = true;
    transcript_changed = false;
    show_topology = false;
}

extern "C" void board_snapshot(const char *line, const char *error, const char *id,
                                const char *text, const char *overview, const char *topology, const char *text_inks, const char *overview_inks, const char *topology_inks) {
    live = true;
    if (transcript_id != id || live_transcript != text || transcript_inks != text_inks) {
        transcript_changed = true;
        transcript_width = 0;
        live_transcript = text;
        transcript_inks = text_inks;
    }
    live_line = line;
    live_error = error;
    transcript_id = id;
    live_overview = overview;
    live_topology = topology;
    overview_colors = overview_inks;
    topology_colors = topology_inks;
    live_calls.clear();
}

extern "C" void board_add_call(const char *id, const char *subject, const char *status, const char *floor, const char *participants, const char *route, const char *progress) {
    live_calls.push_back({id, subject, status, floor, participants, route, progress});
}

extern "C" int board_selected() { return selected_call; }
extern "C" void board_select(int index) { selected_call = index; }

extern "C" void board_close() {
    screen.reset();
    ImTui_ImplText_Shutdown();
    ImGui::DestroyContext();
}

extern "C" int board_frame(int width, int height, float seconds, int mouse_x, int mouse_y,
                            int mouse_down, float wheel, int toggle_calls, int toggle_chat,
                            const uint32_t **colors, const uint32_t **glyphs) {
    if (width * height > screen->nmax) {
        // The fork's resize frees the color plane only.
        delete[] screen->str_data;
        screen->str_data = nullptr;
    }

    auto &io = ImGui::GetIO();
    io.DisplaySize = ImVec2(width, height);
    io.DeltaTime = seconds;
    io.MousePos = ImVec2(mouse_x + 0.5f, mouse_y + 0.5f);
    io.MouseDown[0] = mouse_down != 0;
    io.MouseWheel = wheel;
    ImGui::NewFrame();

    bool quit = false;
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(1, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    if (ImGui::BeginMainMenuBar()) {
        ImGui::PushStyleColor(ImGuiCol_Text, static_cast<ImVec4>(fore_yellow));
        const bool app_menu = ImGui::BeginMenu("Switchboard");
        ImGui::PopStyleColor();
        if (app_menu) {
            ImGui::PushStyleColor(ImGuiCol_Text, static_cast<ImVec4>(fore_red));
            quit = ImGui::MenuItem("Quit", "q");
            ImGui::PopStyleColor();
            ImGui::EndMenu();
        }
        if (live && ImGui::BeginMenu("Actions")) {
            for (View v : {CreateLine, AddAgent, ManageLines, ManageAgents, Connect, Compose})
                if (ImGui::MenuItem(windows[v].title))
                    present(v);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            toggle_calls |= ImGui::MenuItem("Toggle Calls", "1");
            toggle_chat |= ImGui::MenuItem("Toggle Transcript", "2");
            if (live) {
                for (int i=0;i<5;++i)
                    if (ImGui::MenuItem(windows[i].title,
                                        (std::string("F") + std::to_string(i + 3)).c_str(), desk[i].open))
                        board_toggle_view(i);
            }
            reset_layout |= ImGui::MenuItem("Reset layout");
            ImGui::EndMenu();
        }
        if (live && ImGui::MenuItem("Help", "F1"))
            board_help();
        ImGui::EndMainMenuBar();
    }
    ImGui::PopStyleVar(2);

    const float left = std::min(36, std::max(18, width / 3));
    const float pane_height = std::max(5, height - 3);
    const bool status_right = live && width >= 112;
    const bool status_below = live && !status_right && height >= 17;
    const float status_width = status_right ? 38 : left;
    const float calls_height = status_below ? std::max(7.0f, pane_height / 2) : pane_height;
    place_pane(calls_layout, ImVec2(0, 2), ImVec2(left, calls_height), toggle_calls, " Calls");
    const bool calls_expanded = begin_pane(" Calls");
    pane_frame("Calls", calls_expanded);
    if (calls_expanded) {
        clip_pane_content();
        ImGui::Indent(4);
        const int count = live ? static_cast<int>(live_calls.size()) : 3;
        if (live)
            ImGui::TextDisabled("%d conversations", count);
        else
            ImGui::TextDisabled("3 sample calls");
        divider();
        if (live && !count && live_error.empty()) {
            ImGui::TextWrapped("No calls on this line.");
            if (ImGui::Button("Add Agent"))
                launch_form(AddAgent, "Add Agent");
            if (ImGui::Button("Create a Line"))
                present(CreateLine);
        }
        for (int i = 0; i < count; ++i) {
            const LiveCall sample = live ? LiveCall{} : LiveCall{
                std::to_string(i), calls[i], "Sample", "",
                std::string(transcript[i][0]) + " ⇄ " + transcript[i][2], "Demo", ""};
            const auto &call = live ? live_calls[i] : sample;
            ImGui::PushID(call.id.c_str());
            if (ImGui::Selectable("##call", selected_call == i, 0, ImVec2(0, 4)))
                selected_call = i;
            if (ImGui::IsItemVisible()) {
                const auto origin = ImGui::GetItemRectMin();
                const auto end = ImGui::GetItemRectMax();
                auto *draw = ImGui::GetWindowDrawList();
                draw->PushClipRect(origin, end, true);
                const std::string label = (selected_call == i ? "› " : "☏ ") + call.subject;
                draw->AddText(origin, ImGui::GetColorU32(i == selected_call ? static_cast<ImVec4>(fore_yellow) : ImGui::GetStyleColorVec4(ImGuiCol_Text)), label.c_str());
                const ImU32 guide = ImGui::GetColorU32(static_cast<ImVec4>(fore_blue));
                for (int row = 1; row <= 3; ++row)
                    draw->AddText(ImVec2(origin.x, origin.y + row), guide, "│");
                draw->AddText(ImVec2(origin.x + 2, origin.y + 1), ImGui::GetColorU32(static_cast<ImVec4>(fore_blue)), call.participants.c_str());
                const auto state = call_state(call);
                draw->AddText(ImVec2(origin.x + 2, origin.y + 2), ImGui::GetColorU32(state_color(call)), state.c_str());
                draw->AddText(ImVec2(origin.x + 2, origin.y + 3), ImGui::GetColorU32(static_cast<ImVec4>(fore_blue)), call.route.c_str());
                draw->PopClipRect();
            }
            ImGui::PopID();
        }
        ImGui::PopClipRect();
    }
    ImGui::End();

    place_pane(transcript_layout, ImVec2(left, 2), ImVec2(std::max(18.0f, width - left - 1 - (status_right ? status_width : 0)), pane_height),
               toggle_chat, " Transcript");
    const bool transcript_expanded = begin_pane(" Transcript", ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse);
    pane_frame("Transcript", transcript_expanded);
    if (transcript_expanded) {
        clip_pane_content();
        ImGui::Indent(4);
        if (live) {
            if (!live_error.empty())
                ImGui::TextColored(fore_red, "%s", live_error.c_str());
            if (selected_call >= 0 && selected_call < static_cast<int>(live_calls.size())) {
                const auto &call = live_calls[selected_call];
                ImGui::TextColored(fore_yellow, "%s", call.subject.c_str());
                ImGui::TextColored(fore_blue, "%s", call.participants.c_str());
                ImGui::TextColored(state_color(call), "%s · %s", call.route.c_str(), call_state(call).c_str());
                // Korre Audio Queue's SHF switch: a separate lamp beside a fixed button.
                const auto lamp_pos = ImGui::GetCursorScreenPos();
                ImGui::Dummy(ImVec2(1, ImGui::GetTextLineHeight()));
                ImGui::SameLine(0, 0);
                ImGui::PushStyleColor(ImGuiCol_Button, static_cast<ImVec4>(ImColor(80, 80, 80)));
                ImGui::PushStyleColor(ImGuiCol_ButtonHovered, static_cast<ImVec4>(ImColor(120, 120, 120)));
                ImGui::PushStyleColor(ImGuiCol_ButtonActive, static_cast<ImVec4>(ImColor(71, 167, 169)));
                if (ImGui::Button(" Follow ")) {
                    follow = !follow;
                    transcript_changed = true;
                }
                ImGui::PopStyleColor(3);
                divider();
                if (begin_conversation()) {
                    if (call.id != transcript_id)
                        ImGui::TextDisabled("Loading transcript...");
                    else if (live_transcript.empty())
                        ImGui::TextDisabled("No entries");
                    else
                        draw_transcript();
                    if (call.id == transcript_id) {
                        // ImGui applies wheel/scrollbar input when the child begins. Only
                        // user scrolling here changes Follow; a refresh may also move ScrollMax.
                        auto *body = ImGui::GetCurrentWindow();
                        const auto &g = *ImGui::GetCurrentContext();
                        const bool wheeling = wheel != 0 && g.WheelingWindow == body;
                        const bool dragging = g.ActiveId == ImGui::GetWindowScrollbarID(body, ImGuiAxis_Y);
                        if (wheeling || dragging) {
                            const bool at_bottom = ImGui::GetScrollY() >= ImGui::GetScrollMaxY() - 0.5f;
                            follow = at_bottom && !(wheeling && wheel > 0);
                        }
                        if (follow && transcript_changed)
                            ImGui::SetScrollHereY(1.0f);
                        transcript_changed = false;
                    }
                }
                ImGui::EndChild();
                // Paint after input so the lamp reflects the scroll position in this frame.
                ImGui::GetWindowDrawList()->AddText(lamp_pos, follow ? fore_green : fore_red, "█");
            } else {
                ImGui::TextDisabled("No conversation selected");
            }
        } else {
            ImGui::TextColored(fore_yellow, "%s", calls[selected_call]);
            divider();
            if (begin_conversation()) {
                for (int i = 0; i < 4; ++i) {
                    const char *line = transcript[selected_call][i];
                    if (i % 2 == 0) {
                        if (i != 0)
                            ImGui::Spacing();
                        ImGui::TextColored(i == 0 ? fore_blue : fore_green, "%s", line);
                    } else {
                        ImGui::TextUnformatted(line ? line : wide_sample.c_str());
                    }
                }
            }
            ImGui::EndChild();
        }
        ImGui::PopClipRect();
    }
    ImGui::End();
    if (status_right || status_below) {
        const ImVec2 status_pos = status_right ? ImVec2(width - status_width - 1, 2)
                                               : ImVec2(0, 2 + calls_height);
        const ImVec2 status_size(status_width, status_right ? pane_height : pane_height - calls_height);
        place_pane(status_layout, status_pos, status_size, false, " Line status");
        const bool expanded = begin_pane(" Line status");
        pane_frame("Line status", expanded);
        if (expanded) {
            clip_pane_content();
            ImGui::Indent(4);
            ImGui::TextColored(fore_blue, "%s", live_line.c_str());
            if (!live_error.empty())
                ImGui::TextColored(fore_red, "%s", live_error.c_str());
            if (!live_topology.empty() && ImGui::BeginCombo("##status", show_topology ? "Topology" : "Overview")) {
                if (ImGui::Selectable("Overview", !show_topology))
                    show_topology = false;
                if (ImGui::Selectable("Topology", show_topology))
                    show_topology = true;
                ImGui::EndCombo();
            }
            divider();
            if (show_topology && !live_topology.empty()) status_lines(live_topology, topology_colors);
            else status_lines(live_overview, overview_colors);
            ImGui::PopClipRect();
        }
        ImGui::End();
    }
    if (live) draw_views(width,height);
    reset_layout = false;

    ImGui::Render();
    ImTui_ImplText_RenderDrawData(ImGui::GetDrawData(), screen.get());
    *colors = screen->data;
    *glyphs = screen->str_data;
    std::fill_n(io.KeysDown,IM_ARRAYSIZE(io.KeysDown),false);
    return quit;
}
