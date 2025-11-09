## Testing
Run this to evaluate the tests
```
pytest -ra
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
ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can manage own profile" ON public.profiles
  FOR ALL USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS public.handle_new_user();

-- 4. Create function: default workspace + folder
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
  workspace_id UUID;
BEGIN
  -- Create default workspace
  INSERT INTO public.workspaces_workspace (owner_id, name)
  VALUES (NEW.id, 'Default Workspace')
  RETURNING id INTO workspace_id;

  -- Create default folder
  INSERT INTO public.workspaces_folder (workspace_id, name, is_pinned)
  VALUES (workspace_id, 'Default Folder', FALSE);

  -- Insert profile (your existing logic)
  INSERT INTO public.profiles (
    id, email, first_name, last_name, is_active, created_at, updated_at
  ) VALUES (
    NEW.id,
    NEW.email,
    COALESCE(NEW.raw_user_meta_data->>'first_name',
             SPLIT_PART(COALESCE(NEW.raw_user_meta_data->>'full_name', ''), ' ', 1)),
    COALESCE(NEW.raw_user_meta_data->>'last_name',
             TRIM(SUBSTRING(COALESCE(NEW.raw_user_meta_data->>'full_name', ''),
                            POSITION(' ' IN COALESCE(NEW.raw_user_meta_data->>'full_name', '')) + 1))),
    TRUE,
    NOW(),
    NOW()
  );

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 5. Re-attach trigger
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
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