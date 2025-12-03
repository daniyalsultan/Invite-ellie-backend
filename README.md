## Local Development
- Install python == 3.10.*
- Clone the repo into your local drive.
- Open the command prompt, go into the cloned repo and run `python -m venv .venv`. This should create the virtual environment.
- Once done run: `.venv\Scripts\activate` to activate the environment. For Linux: `source .venv/bin/activate`.
- Next run: `pip install -r requirements.txt`. This will install all the required packages.
- Once finished installation, create a `.env` file in the root of the project. This will contain all the environment variables. File is not included in the repo to avoid exposing sensitive information
- Setup is done. Run the server with: `python manage.py runserver`
- Environment needs to be activated before running the project like so:

```
.venv\Scripts\activate
python manage.py runserver
```


## Supabase Code
### Workspaces and Folders policies
```
ALTER TABLE public.workspaces_workspace ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.workspaces_folder ENABLE ROW LEVEL SECURITY;

CREATE POLICY "owner_workspaces" ON public.workspaces_workspace
  FOR ALL USING (owner_id = auth.uid()) WITH CHECK (owner_id = auth.uid());

CREATE POLICY "owner_folders" ON public.workspaces_folder
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM public.workspaces_workspace
      WHERE id = workspaces_folder.workspace_id AND owner_id = auth.uid()
    )
  ) WITH CHECK (
    EXISTS (
      SELECT 1 FROM public.workspaces_workspace
      WHERE id = workspaces_folder.workspace_id AND owner_id = auth.uid()
    )
  );
```

### Profile Model Trigger
This is for sync between the native supabase auth table and our own profile table
```
-- 1. Drop old version
DROP FUNCTION IF EXISTS public.sync_user_to_profile() CASCADE;

-- 2. Create new function with all fields
CREATE OR REPLACE FUNCTION public.sync_user_to_profile()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  ws_id UUID;
  provider_name TEXT;
BEGIN
  ------------------------------------------------------------------
  -- 1. Get SSO provider
  ------------------------------------------------------------------
  SELECT provider INTO provider_name
  FROM auth.identities
  WHERE user_id = NEW.id
  ORDER BY created_at ASC
  LIMIT 1;

  ------------------------------------------------------------------
  -- 2. Create default workspace (idempotent)
  ------------------------------------------------------------------
  INSERT INTO public.workspaces_workspace (owner_id, name, created_at, updated_at)
  VALUES (NEW.id, 'Default Workspace', NOW(), NOW())
  ON CONFLICT (owner_id, name) DO NOTHING
  RETURNING id INTO ws_id;

  IF ws_id IS NULL THEN
    SELECT id INTO ws_id
    FROM public.workspaces_workspace
    WHERE owner_id = NEW.id AND name = 'Default Workspace'
    LIMIT 1;
  END IF;

  ------------------------------------------------------------------
  -- 3. Create default folder (idempotent)
  ------------------------------------------------------------------
  IF ws_id IS NOT NULL THEN
    INSERT INTO public.workspaces_folder (workspace_id, name, is_pinned, created_at, updated_at)
    VALUES (ws_id, 'Default Folder', FALSE, NOW(), NOW())
    ON CONFLICT (workspace_id, name) DO NOTHING;
  END IF;

  ------------------------------------------------------------------
  -- 4. UPSERT Profile (ALL fields)
  ------------------------------------------------------------------
  INSERT INTO public.profiles (
    id, email,
    first_name, last_name,
    avatar_url,
    company, company_notes, position,
    audience, purpose,
    sso_provider,
    is_active, confirmed_at,
    created_at, updated_at,
    first_login, show_tour
  )
  VALUES (
    NEW.id,
    NEW.email,

    -- Name logic
    COALESCE(
      NEW.raw_user_meta_data->>'first_name',
      SPLIT_PART(COALESCE(NEW.raw_user_meta_data->>'full_name', ''), ' ', 1)
    ),
    COALESCE(
      NEW.raw_user_meta_data->>'last_name',
      TRIM(SUBSTRING(COALESCE(NEW.raw_user_meta_data->>'full_name', ''), POSITION(' ' IN COALESCE(NEW.raw_user_meta_data->>'full_name', '')) + 1))
    ),

    NEW.raw_user_meta_data->>'avatar_url',

    NEW.raw_user_meta_data->>'company',
    NEW.raw_user_meta_data->>'company_notes',
    NEW.raw_user_meta_data->>'position',
    NEW.raw_user_meta_data->>'audience',
    NEW.raw_user_meta_data->>'purpose',

    CASE WHEN provider_name = 'azure' THEN 'microsoft' ELSE COALESCE(provider_name, 'email') END,

    COALESCE(NEW.confirmed_at IS NOT NULL, FALSE),
    NEW.confirmed_at,

    COALESCE(NEW.created_at, NOW()),
    NOW(),

    TRUE,   -- first_login
    TRUE    -- show_tour
  )
  ON CONFLICT (id) DO UPDATE SET
    email          = EXCLUDED.email,
    first_name     = EXCLUDED.first_name,
    last_name      = EXCLUDED.last_name,
    avatar_url     = EXCLUDED.avatar_url,
    company        = EXCLUDED.company,
    company_notes  = EXCLUDED.company_notes,
    position       = EXCLUDED.position,
    audience       = EXCLUDED.audience,
    purpose        = EXCLUDED.purpose,
    sso_provider   = EXCLUDED.sso_provider,
    is_active      = EXCLUDED.is_active,
    confirmed_at   = EXCLUDED.confirmed_at,
    updated_at     = EXCLUDED.updated_at,
    -- Only set first_login/show_tour on INSERT
    first_login    = profiles.first_login,
    show_tour      = profiles.show_tour;

  RETURN NEW;
END;
$$;
```

```
DROP TRIGGER IF EXISTS sync_user_to_profile_trigger ON auth.users;

CREATE TRIGGER sync_user_to_profile_trigger
  AFTER INSERT OR UPDATE ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.sync_user_to_profile();
```

### Avatar upload policy
```
-- Allow authenticated users to upload to their own path
CREATE POLICY "Users can upload avatar"
ON storage.objects FOR INSERT
TO authenticated
WITH CHECK (
  bucket_id = 'avatars'
  AND (storage.foldername(name))[1] = auth.uid()::text
);
```

### RLS
```
-- notifications
create policy "Users can view own notifications"
on accounts_notification for select
using (auth.uid() = owner_id);

create policy "Users can update own seen status"
on accounts_notification for update
using (auth.uid() = owner_id);

-- activity_logs
create policy "Users can view own activity"
on accounts_activitylog for select
using (auth.uid() = profile_id);

create policy "Service role can update user password"
on auth.users for update
using (true);
```

### Log Management
```
# Search for a user
cat logs/app.json.log | jq 'select(.user_id == "4b84a17d")'

# Search for errors
cat logs/app.json.log | jq 'select(.levelname == "ERROR")'

# Follow live
tail -f logs/app.json.log | jq -r '[.asctime, .levelname, .user_id, .correlation_id, .message] | @tsv'
```

### Searching
```
-- Enable extension
create extension if not exists pg_trgm;

-- Add search_vector to your tables
alter table workspaces_meeting
add column if not exists search_vector tsvector
generated always as (
    setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(transcript, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(summary, '')), 'C')
) stored;

alter table workspaces_folder
add column if not exists search_vector tsvector
generated always as (
    to_tsvector('english', coalesce(name, ''))
) stored;

-- Create GIN indexes (critical for speed)
create index if not exists idx_meeting_search on workspaces_meeting using gin(search_vector);
create index if not exists idx_folder_search on workspaces_folder using gin(search_vector);
create index if not exists idx_meeting_title_trgm on workspaces_meeting using gin(title gin_trgm_ops);
create index if not exists idx_folder_name_trgm on workspaces_folder using gin(name gin_trgm_ops);
```

### TODOs
- ✅ Swagger Documentation
- ✅ Sign up
- ✅ Email confirmation callback
- ✅ Email confirmation resend request
- ✅ Login
- ✅ Get access token from the refresh token
- ✅ Password reset request
- ✅ Password reset callback
- ✅ Profile get and update
- ✅ SSO Google
- ✅ SSO Microsoft
- ✅ Implement Rolling logs
- ✅ Notify admin emails on critical exceptions during logging
- ✅ Request ID and user ID Tracking in logs

- ✅ Workspaces CRUD
- ✅ Folders CRUD
- ✅ Meetings CRUD
- ⚡ Notifications
- ⚡ User Activity Logs

#### Requested changes & fixes
- ✅ Add additional fields to the profile patch, preferences page and the settings page
- ✅ Resend confirm email not being resent
- ✅ forgot password flow issue
- ✅ SSO callback issue

#### Right to Erasure Changes
##### 1. Database & Model Setup
- ⬜ Add GDPR-compliant fields to User model (deletion tracking, legal hold, verification).
- ⬜ Run and verify database migrations.
- ⬜ Ensure indexes for deletion-related fields.

##### 2. Data Export Service (Article 20)
- ⬜ Implement JSON export service for user data.
- ⬜ Configure AWS S3 for temporary storage (7-day expiration).
- ⬜ Test presigned URL generation and download flow.

##### 3. Deletion Workflow
- ⬜ Identity verification (password + email).
- ⬜ Grace period or immediate deletion option.
- ⬜ Implement Celery tasks for background deletion.
- ⬜ Add rate limiting (max 3 requests per 24 hours).
- ⬜ Integrate multi-factor verification.

##### 4. Multi-System Deletion
- ⬜ Recall.ai (meetings & recordings).
- ⬜ OpenAI (conversation history).
- ⬜ AWS S3 (files & artifacts).
- ⬜ Stripe (delete PII, retain financial records).
- ⬜ Third-party integrations (Slack, Notion, HubSpot).
- ⬜ Implement pseudonymization for multi-party meetings.

##### 5. Legal & Compliance
- ⬜ Authorization workflow.
- ⬜ Review every 90 days.
- ⬜ Documentation of retention basis.
- ⬜ Prepare user appeal process.

##### 6. Audit & Logging
- ⬜ Implement DeletionAuditLog for all operations.
- ⬜ Pseudonymize user IDs immediately after deletion.
- ⬜ Schedule IP deletion after 90 days.
- ⬜ Retain pseudonymized logs for 3 years.

##### 7. Notifications
- ⬜ Deletion confirmation.
- ⬜ Grace period reminders.
- ⬜ Notify third-party recipients (Article 19 compliance).

##### 8. Testing & QA
- ⬜ Unit tests (95%+ coverage).
- ⬜ Integration tests across all systems.
- ⬜ Load tests (100+ concurrent deletions).
- ⬜ Security audit & penetration testing.

##### 9. Deployment
- ⬜ Configure external API credentials (Recall.ai, OpenAI, Stripe, AWS).
- ⬜ Validate deletion APIs in staging.
- ⬜ Legal & DPO sign-off on compliance.
- ⬜ Set up monitoring dashboards and SLA alerts.





#### Deployments
- Check DEPLOY.md




### Notes
```
inv1teEllie@dmin!
```