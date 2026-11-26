#ifndef YIP_IMTUI_BRIDGE_H
#define YIP_IMTUI_BRIDGE_H
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

void board_init(const char *unicode_sample, uint32_t foreground[256]);
void board_close(void);
void board_action(const char *group, const char *label);
void board_field(const char *label, int checkbox);
int board_take_action(void);
const char *board_value(int index);
void board_result(const char *text, int state);
void board_lines(const char *lines, const char *relays, const char *client,const char *labels);
void board_extra(int index, const char *text, const char *inks);
int board_views(void);
void board_toggle_view(int index);
void board_key(int code, unsigned int rune);
int board_editing(void);
void board_help(void);
int board_dismiss(void);
void board_snapshot(const char *line, const char *error, const char *transcript_id,
                    const char *transcript, const char *overview, const char *topology, const char *text_inks, const char *overview_inks, const char *topology_inks);
void board_add_call(const char *id, const char *subject, const char *status, const char *floor, const char *participants, const char *route, const char *progress);
int board_selected(void);
void board_select(int index);
int board_frame(int width, int height, float seconds, int mouse_x, int mouse_y,
                int mouse_down, float wheel, int toggle_calls, int toggle_chat,
                const uint32_t **colors, const uint32_t **glyphs);

#ifdef __cplusplus
}
#endif
#endif
