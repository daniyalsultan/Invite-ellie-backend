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