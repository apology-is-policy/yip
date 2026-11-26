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
        if (wrap) ImGui::PushTextWrapPos(std::max(ImGui::GetCursorPosX()+1,ImGui::GetWindowWidth()-4));
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
void pane_frame(const char *title, bool expanded) {
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
    const auto visible_title = std::string(title).substr(0, width - 11);
    top += visible_title;
    top += expanded ? " ╞" : " ├";
    for (int x = 10 + static_cast<int>(visible_title.size()); x < width - 2; ++x)
        top += expanded ? "═" : "─";
    top += expanded ? "╗" : "╴";
    glyph(4, 0, top.c_str());
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

bool begin_pane(const char *name, ImGuiWindowFlags flags = 0) {
    const ImVec4 transparent(0, 0, 0, 0);
    ImGui::PushStyleColor(ImGuiCol_Text, transparent);
    ImGui::PushStyleColor(ImGuiCol_TitleBg, transparent);
    ImGui::PushStyleColor(ImGuiCol_TitleBgActive, transparent);
    ImGui::PushStyleColor(ImGuiCol_TitleBgCollapsed, transparent);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(2, 0));
    const bool expanded = ImGui::Begin(name, nullptr, ImGuiWindowFlags_NoBackground | flags);
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
            if (start == eol)
                transcript_rows.push_back({"", ink});
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
std::vector<std::string> known_lines;
const char *views[] = {"Line topology", "Relay health", "Broadcasts", "Roadmaps", "Configuration"};
bool open_view[5]{};
std::string extra_text[4], extra_inks[4], result;
int active_form = 0, submitted = -1, result_state = 0;
bool reviewing = false;
void choose_action(int index) {
    active_form = index;
    reviewing = false;
    if (result_state != 1)
        result.clear();
}
void config_form() {
    if (actions.empty())
        return;
    if (result_state != 1 && !reviewing) {
        if (ImGui::BeginCombo("Section", actions[active_form].group.c_str())) {
            for (int i = 0; i < (int)actions.size(); ++i) {
                if (i && actions[i - 1].group == actions[i].group)
                    continue;
                if (ImGui::Selectable(actions[i].group.c_str(),
                                      actions[i].group == actions[active_form].group))
                    choose_action(i);
            }
            ImGui::EndCombo();
        }
        if (ImGui::BeginCombo("Action", actions[active_form].label.c_str())) {
            for (int i = 0; i < (int)actions.size(); ++i) {
                if (actions[i].group == actions[active_form].group &&
                    ImGui::Selectable(actions[i].label.c_str(), active_form == i))
                    choose_action(i);
            }
            ImGui::EndCombo();
        }
    }
    auto &action = actions[active_form];
    ImGui::TextColored(fore_yellow, "%s", action.label.c_str());
    divider();
    if (action.label == "Create workstation request")
        ImGui::TextWrapped("Compare the descriptor fingerprint through a trusted channel. Send the request "
                           "file and verify both workstation fingerprints with the operator.");
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
        ImGui::PushID(field.label.c_str());
        if (reviewing || result_state == 1) {
            ImGui::TextWrapped("%s: %s", field.label.c_str(),
                               field.checkbox ? (field.checked ? "yes" : "no") : field.value.data());
        } else if (field.checkbox) {
            ImGui::Checkbox(field.label.c_str(), &field.checked);
        } else {
            ImGui::TextColored(fore_blue, "%s", field.label.c_str());
            ImGui::SetNextItemWidth(std::max(8.0f, ImGui::GetContentRegionAvail().x - 3));
            ImGui::InputText("##value", field.value.data(), field.value.size());
            if (field.label == "Local line" && !known_lines.empty() &&
                ImGui::BeginCombo("##known", "Choose existing line")) {
                for (const auto &line : known_lines)
                    if (ImGui::Selectable(line.c_str()))
                        std::snprintf(field.value.data(), field.value.size(), "%s", line.c_str());
                ImGui::EndCombo();
            }
        }
        ImGui::PopID();
    }
    ImGui::PopID();
    if (result_state != 1) {
        if (reviewing) {
            if (ImGui::Button("Apply")) {
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
        ImGui::TextWrapped("%s", result.c_str());
        ImGui::PopStyleColor();
    }
}
void draw_views(int width, int height) {
    for (int i = 0; i < 5; ++i) {
        if (!open_view[i])
            continue;
        std::string name = std::string(" ") + views[i];
        ImGui::SetNextWindowPos(ImVec2(std::min(5 + i, width / 12), 3 + i % 3), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(std::min(82, width - 8), std::max(6, height - 8)),
                                 ImGuiCond_FirstUseEver);
        bool expanded = begin_pane(name.c_str());
        pane_frame(views[i], expanded);
        if (expanded) {
            clip_pane_content();
            ImGui::Indent(3);
            if (ImGui::Button("Close"))
                open_view[i] = false;
            if (i == 2 && ImGui::Button("Compose broadcast")) {
                for (int j = 0; j < (int)actions.size(); ++j)
                    if (actions[j].group == "Broadcasts") {
                        if (result_state != 1)
                            choose_action(j);
                        break;
                    }
                open_view[4] = true;
            }
            divider();
            if (i == 4)
                config_form();
            else if (extra_text[i].empty())
                ImGui::TextDisabled("%s", i == 2 ? "No broadcasts" : "Awaiting line data");
            else
                status_lines(extra_text[i], extra_inks[i], true);
            ImGui::PopClipRect();
        }
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
    const auto &f = actions[active_form].fields.at(i);
    return f.checkbox ? (f.checked ? "1" : "") : f.value.data();
}
extern "C" void board_result(const char *text, int state) {
    result = text;
    result_state = state;
}
extern "C" void board_lines(const char *lines) {
    known_lines.clear();
    std::istringstream input(lines);
    for (std::string line; std::getline(input, line);)
        if (!line.empty())
            known_lines.push_back(line);
}
extern "C" void board_extra(int i, const char *text, const char *inks) {
    extra_text[i] = text;
    extra_inks[i] = inks;
}
extern "C" void board_toggle_view(int i) {
    if (i >= 0 && i < 5)
        open_view[i] = !open_view[i];
}
extern "C" int board_views() {
    return (open_view[2] ? 1 : 0) | (open_view[3] ? 2 : 0) | (open_view[1] ? 4 : 0);
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
    actions.clear();
    active_form = 0;
    submitted = -1;
    reviewing = false;
    result.clear();
    result_state = 0;
    std::fill_n(open_view, 5, false);
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
        if (ImGui::BeginMenu("View")) {
            toggle_calls |= ImGui::MenuItem("Toggle Calls", "1");
            toggle_chat |= ImGui::MenuItem("Toggle Transcript", "2");
            if (live) {
                for (int i=0;i<5;++i)
                    ImGui::MenuItem(views[i],(std::string("F")+std::to_string(i+3)).c_str(),&open_view[i]);
            }
            reset_layout |= ImGui::MenuItem("Reset layout");
            ImGui::EndMenu();
        }
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
