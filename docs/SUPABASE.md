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
-- FINAL 100% COMPLETE TRIGGER — ALL FIELDS INCLUDED — NO REMOVALS
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS public.sync_user_to_profile() CASCADE;

CREATE OR REPLACE FUNCTION public.sync_user_to_profile()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
  ws_id UUID;
  provider_name TEXT;
BEGIN
  -- Get SSO provider
  SELECT provider INTO provider_name
  FROM auth.identities
  WHERE user_id = NEW.id
  ORDER BY created_at ASC
  LIMIT 1;

  -- 1. CREATE PROFILE FIRST — ALL FIELDS, NOTHING REMOVED
  INSERT INTO public.profiles (
    id, email, first_name, last_name, avatar_url,
    company, company_notes, position, audience, purpose,
    sso_provider, is_active, confirmed_at,
    created_at, updated_at,
    first_login, show_tour,

    -- GDPR FIELDS — ALL INCLUDED
    deletion_requested_at, deletion_requested_by_ip, deletion_type,
    data_exported, data_export_completed_at,
    deleted_at, deletion_completed_at, deletion_verified_at,
    legal_hold, legal_hold_reason, legal_hold_reason_user_facing,
    legal_hold_case_number, legal_hold_placed_at,
    legal_hold_placed_by_id, legal_hold_approved_by_id,
    retention_basis, legal_hold_review_date,
    deletion_verification_token, deletion_verification_sent_at,
    deletion_verification_confirmed_at,
    excluded_from_backups, backup_exclusion_verified_at,
    user_country, is_eu_resident, privacy_regulation,
    subscription_auto_renew, subscription_status
  )
  VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'first_name', SPLIT_PART(COALESCE(NEW.raw_user_meta_data->>'full_name', ''), ' ', 1)),
    COALESCE(NEW.raw_user_meta_data->>'last_name', TRIM(SUBSTRING(COALESCE(NEW.raw_user_meta_data->>'full_name', ''), POSITION(' ' IN COALESCE(NEW.raw_user_meta_data->>'full_name', '')) + 1))),
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
    TRUE,           -- first_login
    TRUE,           -- show_tour

    -- GDPR DEFAULTS — ALL INCLUDED
    NULL, NULL, 'GRACE_PERIOD',           -- deletion_requested_at, deletion_requested_by_ip, deletion_type ← FIXED!
    FALSE, NULL,                          -- data_exported, data_export_completed_at
    NULL, NULL, NULL,                     -- deleted_at, deletion_completed_at, deletion_verified_at
    FALSE, '', '',                        -- legal_hold, legal_hold_reason, legal_hold_reason_user_facing
    '', NULL,                             -- legal_hold_case_number, legal_hold_placed_at
    NULL, NULL,                           -- legal_hold_placed_by_id, legal_hold_approved_by_id
    '', NULL,                             -- retention_basis, legal_hold_review_date
    '', NULL, NULL,                       -- deletion_verification_token, deletion_verification_sent_at, deletion_verification_confirmed_at
    FALSE, NULL,                          -- excluded_from_backups, backup_exclusion_verified_at
    '', FALSE, 'GDPR',                     -- user_country, is_eu_resident, privacy_regulation,
    FALSE, ''
  )
  ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    first_name = EXCLUDED.first_name,
    last_name = EXCLUDED.last_name,
    avatar_url = EXCLUDED.avatar_url,
    company = EXCLUDED.company,
    company_notes = EXCLUDED.company_notes,
    position = EXCLUDED.position,
    audience = EXCLUDED.audience,
    purpose = EXCLUDED.purpose,
    sso_provider = EXCLUDED.sso_provider,
    is_active = EXCLUDED.is_active,
    confirmed_at = EXCLUDED.confirmed_at,
    updated_at = EXCLUDED.updated_at;

  -- 2. Now create default workspace (profile exists → FK happy)
  INSERT INTO public.workspaces_workspace (owner_id, name, created_at, updated_at)
  VALUES (NEW.id, 'Default Workspace', NOW(), NOW())
  ON CONFLICT (owner_id, name) DO NOTHING
  RETURNING id INTO ws_id;

  IF ws_id IS NULL THEN
    SELECT id INTO ws_id FROM public.workspaces_workspace
    WHERE owner_id = NEW.id AND name = 'Default Workspace' LIMIT 1;
  END IF;

  IF ws_id IS NOT NULL THEN
    INSERT INTO public.workspaces_folder (workspace_id, name, is_pinned, created_at, updated_at)
    VALUES (ws_id, 'Default Folder', FALSE, NOW(), NOW())
    ON CONFLICT (workspace_id, name) DO NOTHING;
  END IF;

  RETURN NEW;
END;
$$;

-- Re-attach trigger
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.sync_user_to_profile();
```

### Turn CASCADE on
```
ALTER TABLE public.workspaces_folder
DROP CONSTRAINT IF EXISTS workspaces_folder_workspace_id_c40844d0_fk_workspace;
ALTER TABLE public.workspaces_folder
ADD CONSTRAINT workspaces_folder_workspace_id_fk
FOREIGN KEY (workspace_id) REFERENCES public.workspaces_workspace(id) ON DELETE CASCADE;

-- Workspace → Profile (owner)
ALTER TABLE public.workspaces_workspace
DROP CONSTRAINT IF EXISTS workspaces_workspace_owner_id_d8b120c0_fk_profiles_id;
ALTER TABLE public.workspaces_workspace
ADD CONSTRAINT workspaces_workspace_owner_id_fk
FOREIGN KEY (owner_id) REFERENCES public.profiles(id) ON DELETE CASCADE;

-- Folder → Meeting (if you have meetings)
ALTER TABLE public.workspaces_meeting
DROP CONSTRAINT IF EXISTS workspaces_meeting_folder_id_fk;
ALTER TABLE public.workspaces_meeting
ADD CONSTRAINT workspaces_meeting_folder_id_fk
FOREIGN KEY (folder_id) REFERENCES public.workspaces_folder(id) ON DELETE CASCADE;
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