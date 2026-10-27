# Data retention and purge

What is deleted, when, on whose instruction, and how to prove it afterwards.
Written because the retention promise in the privacy policy had no document
behind it, and "what actually happens to a customer's data" was answerable
only by reading code in two repositories.

Everything here is current as of 2026-10-27 and names the code that does it,
so a future reader can check rather than trust.

---

## 1. What is deleted

**Recordings only** — the video and audio of a meeting, both the copy
Recall.ai holds and the artifacts downloaded into our storage
(`RecordingArtifact` rows of type `video_mixed`, `audio_mixed`,
`audio_separate`).

**What is never deleted by retention:** transcripts, summaries, action items,
and the structured records (commitments, decisions, blockers, promises, risks)
drawn from them. The privacy policy lists recordings and transcripts as
separate controls, and a workspace that forgot every commitment after thirty
days would not be the product.

The `BotRecording` row itself is kept and stamped with `media_expired_at`, so
a deletion is provable rather than merely claimed.

Account deletion (section 5) is different and does remove everything.

## 2. At which level the period is set

Two levels, nearest wins:

| Level | Field | Default |
|---|---|---|
| Workspace | `Workspace.recording_retention_days` | `NULL` — not set |
| User | `Profile.recording_retention_days` | `30` |

A workspace that sets a period governs **every recording filed to it**,
whoever recorded it. A workspace that sets nothing (`NULL`, which is every
workspace until an owner changes it) defers to the recording user's own
profile setting.

Only a **workspace owner** may change the workspace period
(`WorkspaceSerializer.validate_recording_retention_days`); members are
refused. Permitted range 1–3650 days, or unset.

recall-server does the deleting and cannot read the backend database, so it
asks `/api/accounts/internal/user-info/<user_id>/?workspace_id=<id>` and the
backend resolves the precedence in one place, returning both the number and a
`retention_source` of `workspace` or `profile`.

**Known conflict, open with the client:** the Post Beta SOW says the default
should be "life of the workspace". It is 30 days, following an explicit
decision during the build to match the published privacy policy. The default
has not been changed pending that conversation.

## 3. On what trigger

A scheduled sweep, `daily-expire-recordings`, at **05:30 UTC daily**
(`CELERY_BEAT_SCHEDULE` in `core/settings.py`). It calls
`accounts.tasks.expire_recordings`, which posts to recall-server's
`/api/internal/expire-recordings`. The work happens in
`app/logic/retention.py`.

The task raises rather than returning quietly on failure, because a retention
sweep that silently stops running is not noticed until a customer asks why
something they were promised would be gone is still there.

Three things stop a recording being expired, each deliberate:

* **a legal hold** on the account (`Profile.legal_hold`);
* **a failed policy lookup** — if the backend cannot be reached, nothing is
  deleted, because deleting on a guess is not recoverable;
* **a recording made before 2026-10-20** (`retention.EFFECTIVE_FROM`) —
  expiry applies to new data only, as a date someone can read rather than
  "whenever the job first ran".

Recall.ai is asked to delete first. If that fails, nothing is marked expired
locally: telling a customer their recording is gone while it still sits with a
sub-processor is the one outcome worse than it not being deleted yet.

## 4. Grace period

**Retention expiry has no grace period.** A recording past its period is
deleted on the next sweep. The period itself is the notice.

**Account deletion has a 7-day grace period** when the user chooses
`GRACE_PERIOD` (`accounts.tasks.check_deletion_grace_periods`, daily at 03:00
UTC). Choosing `IMMEDIATE` skips it. A legal hold suspends it indefinitely.

## 5. Where the audit trail lives

`accounts.models.DeletionAuditLog` — one row per action, with `profile`,
`action`, `timestamp` and a JSON `metadata` blob. Rows survive the deletion
of the profile they describe (`on_delete=SET_NULL`) and can be pseudonymized
in place (`pseudonymized`, `pseudonymized_at`), so the record of *what was
done* outlives the data it was done to.

Recording expiry additionally leaves `BotRecording.media_expired_at`, which is
the per-recording proof.

## 6. What a support purge request actually does

There is **no self-service "purge everything now" button for support staff**,
and no management command for it. Honest statement of the current position:

1. A customer asks for erasure.
2. Someone with admin access sets the account to deletion
   (`IMMEDIATE` or `GRACE_PERIOD`) through the account-deletion flow. This is
   the only supported path and it is the user's own flow, used on their behalf.
3. The scheduled task performs it and writes `DeletionAuditLog`.
4. Recordings in recall-server go through the same expiry mechanism.

To purge a **single meeting** rather than an account, the meeting-deletion
endpoint exists and is gated on `can_view` then `can_manage`. Note for
whoever next verifies this: an end-to-end execution of that endpoint has
**never been observed** — authorization is verified, completion is not.

**Gap worth naming:** a support purge today depends on someone driving the
user-facing deletion flow with admin credentials. There is no audited
"support purged X on behalf of Y" action distinct from the user doing it
themselves, so the audit trail cannot tell those two apart.
