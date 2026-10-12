# Example skills

A skill is a packaged instruction set attached to an application. It is text the model reads: it
grants no tools, no data access and no permissions. Anything a skill tells the model to *do* still
has to be attached separately.

Two properties matter when writing one:

- **`description`** is injected into every single request for that application. Keep it to one line
  that says when the skill applies, because it is how the model decides to ask for the body.
- **`body`** is injected only when a request names the skill in its `skills` array. It can be long;
  it costs nothing until it is used.

## Adding one

### Through the dashboard

**Skills & Capabilities** → fill in **Register a skill** → **Register skill**. Then, in
**Application capabilities**, choose the application and the skill and press **Attach**. The row
shows `pinned v1`, and a second badge appears if the catalogue later moves ahead of the pin.

### Through the API

Register it (needs the `ManageSkills` action):

```bash
curl -sk -X POST https://localhost:64022/api/skills -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d @skill.json
```

Attach it to an application (needs `ManageAppCapabilities`):

```bash
curl -sk -X POST https://localhost:64022/api/apps/TEST-01/capabilities -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" -d '{"kind":"Skill","ref":"refund-policy"}'
```

Call the application, naming the skills whose bodies you want loaded:

```bash
curl -sk -X POST https://localhost:64022/gateway/TEST-01/invoke -H "X-API-Key: ug_live_..." -H "Content-Type: application/json" -d '{"input":"Customer wants a refund after 45 days","skills":["refund-policy"]}'
```

## Example 1 — Refund policy (support application)

A policy skill: narrow, factual, and the kind of thing that otherwise gets pasted into every system
prompt and drifts between applications.

```json
{
  "skillId": "refund-policy",
  "name": "Refund policy",
  "description": "Rules for refunds, store credit and escalation. Use when a customer asks for money back.",
  "body": "## Refunds\n\n- Within 30 days of delivery, with proof of purchase: full refund to the original payment method.\n- 31 to 90 days: store credit only, at the price paid.\n- Over 90 days: no refund. Offer a repair or replacement if the item is faulty.\n- Faulty on arrival, any date: full refund plus return postage, no receipt required.\n\n## What not to promise\n\n- Never quote a refund arrival faster than 5 business days.\n- Never waive the restocking fee on opened hardware; that needs a supervisor.\n\n## Escalate\n\nHand to a human when the order value is over 500, when the customer mentions a chargeback, or when they have already been refused once."
}
```

What the model receives when the request names it:

```
You are a support assistant.

## Available skills
Instruction sets attached to this application. They describe how to answer; they grant no tools or other access.
- refund-policy (v1): Rules for refunds, store credit and escalation. Use when a customer asks for money back.

## Skill: Refund policy (refund-policy v1)
## Refunds

- Within 30 days of delivery, with proof of purchase: full refund to the original payment method.
...
```

Without `"skills": ["refund-policy"]` in the request, only the one-line index entry is sent.

## Example 2 — SQL review (engineering application)

A review checklist. Note it describes judgements rather than actions: it does not tell the model to
query anything, because a skill cannot grant database access.

```json
{
  "skillId": "sql-review",
  "name": "SQL review",
  "description": "Checklist for reviewing SQL for correctness, cost and safety. Use when asked to review a query or migration.",
  "body": "## Always flag\n\n- UPDATE or DELETE with no WHERE clause, or a WHERE that cannot use an index.\n- SELECT * on a table over a million rows.\n- A JOIN key with no index on either side.\n- Implicit type conversion in a predicate, which silently disables an index.\n- A migration that rewrites a large table without a stated lock strategy.\n\n## Judgement calls\n\n- OFFSET pagination past a few thousand rows: suggest keyset pagination, do not insist.\n- A transaction spanning more than one external call: raise it, since the lock is held across the network.\n\n## Output shape\n\nList findings worst first. Each one: the line, what goes wrong, and the rewritten clause. If nothing is wrong, say so in one sentence rather than inventing improvements."
}
```

## Example 3 — Incident comms (operations application)

Longer, with a template. This is the shape that benefits most from progressive disclosure: the body
is expensive and rarely needed, so it stays out of the prompt until it is asked for.

```json
{
  "skillId": "incident-comms",
  "name": "Incident communications",
  "description": "How to write customer-facing incident updates. Use during an outage or degradation.",
  "body": "## Rules\n\n- State impact before cause. The reader wants to know whether they are affected.\n- Never name an individual, a vendor, or a root cause that is still a hypothesis.\n- Give the next update time, and make it one you will keep.\n- No apology adjectives. One apology, in the first update, and move on.\n\n## Template\n\n**Investigating** — We are investigating reports of {symptom} affecting {scope}. Next update by {time}.\n\n**Identified** — The cause is {mechanism}. {Scope} remains affected. We are {action}. Next update by {time}.\n\n**Monitoring** — {Fix} is deployed and error rates are back to normal. We are watching for recurrence. Next update by {time}, or sooner if anything changes.\n\n**Resolved** — {Symptom} is resolved as of {time}. {One line on prevention.} A full write-up follows within five working days."
}
```

## Example 4 — Tone of voice (shared across applications)

The smallest useful skill, and the clearest argument for the catalogue: register it once, attach it
to every application, change it in one place.

```json
{
  "skillId": "tone-of-voice",
  "name": "Tone of voice",
  "description": "House style: how to sound. Applies to any customer-facing reply.",
  "body": "Short sentences. No exclamation marks. Say 'we' for the company and 'you' for the customer.\n\nDo not open with pleasantries or restate the question. Answer first, then explain if it is needed.\n\nPrefer the plain word: use rather than utilise, start rather than commence, about rather than regarding. Write out numbers under ten.\n\nIf you do not know, say so and say what you will do next."
}
```

## Writing skills that behave

| Do | Why |
| --- | --- |
| Make the description a trigger condition ("Use when...") | It is the only part the model always sees, and it is how the model knows to ask for the body |
| Keep one subject per skill | Four small skills cost four index lines; one large one costs its whole body whenever any part of it is needed |
| Write rules, not narration | "Never quote under 5 business days" survives summarisation; "we try to be prompt" does not |
| Put the output shape in the body | It is the most common reason a good answer still needs editing |

| Avoid | What happens |
| --- | --- |
| Secrets, keys, connection strings | The guardrails refuse the skill at registration. A skill goes into a system prompt, and system prompts end up in logs and provider requests |
| "Ignore previous instructions", or any injection phrasing | Refused at registration by the prompt-injection detector, whatever the gateway's configured mode |
| Telling the model to call a tool | A skill grants nothing. If the tool is not attached to the application, nothing happens |
| Pasting a whole handbook | Nothing enforces a body limit below 100,000 characters, but the whole body loads at once when named. Split it |

## Versions and pinning

Editing a skill's content creates a new version and keeps the old one. An application keeps sending
the version it pinned when it attached, so a rewrite cannot change behaviour under a running
application. To move an application forward, detach and re-attach:

```bash
curl -sk -X DELETE https://localhost:64022/api/apps/TEST-01/capabilities/BINDING_ID -H "Authorization: Bearer $TOKEN"
```

Disabling a skill in the catalogue takes it out of every prompt immediately, while leaving the
bindings in place; the dashboard then shows the binding as unusable with the reason. Deleting it
leaves bindings that resolve to nothing, which is why disable is usually the right move.
