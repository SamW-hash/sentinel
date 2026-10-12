import re

parsed_events = []

def parse_ssh_event(line: str) -> dict | None:
    pattern = r"^(?P<Timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2}).*:\s+(?P<Event_Type>Failed|Accepted)\s+(?:password|publickey)\s+for\s+(?:invalid user\s+)?(?P<Username>\S+)\s+from\s+(?P<Source_IP>\S+)"
    match = re.match(pattern, line)
    if match:
        return match.groupdict()
    return None

with open('data/auth.log', 'r') as file:
    for line in file:
        event = (parse_ssh_event(line))

        if event is not None:
            parsed_events.append(event)

print(parsed_events)
