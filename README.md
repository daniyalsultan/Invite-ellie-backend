### PROFILE MODEL TRIGGER
'''
-- 1. Drop old trigger/function
DROP TRIGGER IF EXISTS on_auth_user_created ON auth.users;
DROP FUNCTION IF EXISTS public.handle_new_user();

-- 2. Create new function
CREATE OR REPLACE FUNCTION public.handle_new_user()
RETURNS TRIGGER AS $$
DECLARE
  full_name TEXT := COALESCE(NEW.raw_user_meta_data->>'full_name', '');
  first_name_part TEXT;
  last_name_part TEXT;
BEGIN
  -- Split full_name into first / last (if provided)
  IF full_name <> '' THEN
    first_name_part := SPLIT_PART(full_name, ' ', 1);
    last_name_part := TRIM(SUBSTRING(full_name FROM POSITION(' ' IN full_name) + 1));
    IF last_name_part = '' THEN
      last_name_part := first_name_part;
      first_name_part := '';
    END IF;
  ELSE
    first_name_part := '';
    last_name_part := '';
  END IF;

  -- Insert into profiles
  INSERT INTO public.profiles (
    id,
    email,
    first_name,
    last_name,
    is_active,
    created_at,
    updated_at
  ) VALUES (
    NEW.id,
    NEW.email,
    first_name_part,
    last_name_part,
    TRUE,
    NOW(),
    NOW()
  );

  RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- 3. Re-attach trigger
CREATE TRIGGER on_auth_user_created
  AFTER INSERT ON auth.users
  FOR EACH ROW
  EXECUTE FUNCTION public.handle_new_user();

'''