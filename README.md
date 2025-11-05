
## Supabase Code

### Profile Model Trigger

This is for sync between the native supabase auth table and our own profile table
```
-- 1. Drop the trigger that depends on the function
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;

-- 2. Now you can safely drop the function
DROP FUNCTION IF EXISTS public.handle_new_user() CASCADE;

-- 3. (Optional) Drop the old profiles table if you want a clean slate
--     WARNING: This deletes all profile data!
-- DROP TABLE IF EXISTS public.profiles CASCADE;

-- 4. Recreate the profiles table with safe defaults
CREATE TABLE IF NOT EXISTS public.profiles (
  id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  email TEXT NOT NULL,
  first_name TEXT DEFAULT '',
  last_name TEXT DEFAULT '',
  avatar_url TEXT DEFAULT '',
  is_active BOOLEAN DEFAULT TRUE NOT NULL,
  confirmed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
  updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- 5. Disable RLS for Auth server (critical for SSO)
ALTER TABLE public.profiles DISABLE ROW LEVEL SECURITY;

-- 6. Re-enable RLS + add user policy
ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can manage own profile" ON public.profiles
  FOR ALL USING (auth.uid() = id) WITH CHECK (auth.uid() = id);

-- 7. Recreate the trigger function (handles Google SSO full_name)
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
BEGIN
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
  )
  ON CONFLICT (id) DO UPDATE SET
    email = EXCLUDED.email,
    first_name = EXCLUDED.first_name,
    last_name = EXCLUDED.last_name,
    updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 8. Re-attach the trigger
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW EXECUTE FUNCTION public.handle_new_user();
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

- ⬜ Workspaces CRUD
- ⬜ Folders CRUD
- ⬜ Meetings CRUD