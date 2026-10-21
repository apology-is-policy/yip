package main

func deliveryTools() []toolDef {
	return []toolDef{
		{Name: "channel_ack", Description: "Acknowledge the exact probe ID received in a Yip channel event. Only use after receiving that event; do not discover and acknowledge probes from status. Qualifies this MCP connection, not work completion.", InputSchema: obj(map[string]any{"id": str("Probe delivery ID received in the channel event")}, "id")},
		{Name: "deliveries", Description: "Inspect durable delivery IDs and acceptance/acknowledgment state for your registered endpoint.", InputSchema: obj(map[string]any{})},
		{Name: "delivery_ack", Description: "Acknowledge that you read a delivery ID. This is not completion or a resource grant.", InputSchema: obj(map[string]any{"id": str("Delivery ID")}, "id")},
		{Name: "broadcasts", Description: "List broadcasts addressed to you; announcements do not require a reply. Briefings and regroup requests do. Use broadcast_read for the full text.", InputSchema: obj(map[string]any{"all": yesno("Include read and answered history")})},
		{Name: "broadcast_read", Description: "Read an addressed broadcast and record a read receipt, without answering it.", InputSchema: obj(map[string]any{"id": str("Broadcast ID")}, "id")},
		{Name: "broadcast_reply", Description: "Record your response to an addressed briefing or regroup request, or comment on an announcement. Does not change call floors or leases.", InputSchema: obj(map[string]any{"id": str("Broadcast ID"), "body": str("Response")}, "id", "body")},
	}
}
func deliveryCall(me, name string, a map[string]any) (string, bool, error) {
	switch name {
	case "deliveries":
		s, e := DeliveryInbox(me)
		return s, true, e
	case "delivery_ack":
		return "read receipt recorded", true, AckDelivery(me, argStr(a, "id"))
	case "broadcasts":
		return BroadcastInbox(me, argBool(a, "all")), true, nil
	case "broadcast_read":
		s, e := ReadBroadcast(argStr(a, "id"), me)
		return s, true, e
	case "broadcast_reply":
		return "response recorded", true, ReplyBroadcast(argStr(a, "id"), me, argStr(a, "body"))
	}
	return "", false, nil
}
