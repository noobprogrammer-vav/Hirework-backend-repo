# Generated by Django 5.0.4 on 2024-06-28 08:27

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('auth', '0012_alter_user_first_name_max_length'),
    ]

    operations = [
        migrations.CreateModel(
            name='BenefitsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('benefit', models.CharField(max_length=100, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='BreakReasonModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='CitiesModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('city', models.CharField(max_length=100, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='DesignationModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('designation', models.CharField(max_length=100, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='IndustriesModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('industry', models.CharField(max_length=100, unique=True)),
                ('image', models.ImageField(default=None, null=True, upload_to='industries')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='LanguageModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('language', models.CharField(max_length=100, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='PeriodModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('period', models.IntegerField(unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='PlansModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('plan_description', models.TextField(blank=True, null=True)),
                ('job_posting_count', models.IntegerField(default=3)),
                ('application_count', models.IntegerField(default=50)),
                ('database_access_count', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='ScreeningQuestionModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('question', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='SkillsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('skill', models.CharField(max_length=100, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='StatesModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('state', models.CharField(max_length=100, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='SupplimentalPayModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('supplimentary', models.CharField(max_length=100, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='TagsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
        ),
        migrations.CreateModel(
            name='CompanyDetailsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization_name', models.CharField(max_length=255)),
                ('organization_email', models.EmailField(max_length=254, unique=True)),
                ('is_top', models.BooleanField(default=False)),
                ('organization_mobile', models.CharField(blank=True, max_length=100, null=True)),
                ('organization_description', models.TextField(blank=True, null=True)),
                ('alternate_mobile', models.CharField(blank=True, max_length=100, null=True)),
                ('organization_address', models.TextField(blank=True, null=True)),
                ('organization_gst', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('organization_pan', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('organization_logo', models.ImageField(blank=True, default=None, null=True, upload_to='logo')),
                ('organization_website', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('organization_fb', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('organization_insta', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('organization_ln', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('organization_city', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.citiesmodel')),
                ('industry', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.industriesmodel')),
            ],
        ),
        migrations.CreateModel(
            name='JobsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100, unique=True)),
                ('description', models.TextField()),
                ('hired_by', models.IntegerField(default=0)),
                ('annual_salary_type', models.CharField(choices=[('exact', 'Exact'), ('base', 'Base'), ('range', 'Range')], default='exact', max_length=50)),
                ('start_salary', models.FloatField()),
                ('end_salary', models.FloatField(blank=True, null=True)),
                ('number_of_openings', models.IntegerField(default=0)),
                ('experience_from', models.IntegerField(default=0)),
                ('experience_to', models.IntegerField(default=0)),
                ('show_salary', models.BooleanField(default=True)),
                ('address', models.TextField()),
                ('pincode', models.CharField(blank=True, default=None, max_length=50, null=True)),
                ('landmark', models.CharField(max_length=100)),
                ('work_week_start', models.CharField(choices=[('sun', 'Sunday'), ('mon', 'Monday'), ('tue', 'Tueday'), ('wed', 'Wednesday'), ('thur', 'Thursday'), ('fri', 'Friday'), ('sat', 'Saturday')], default='mon', max_length=50)),
                ('work_week_end', models.CharField(choices=[('sun', 'Sunday'), ('mon', 'Monday'), ('tue', 'Tueday'), ('wed', 'Wednesday'), ('thur', 'Thursday'), ('fri', 'Friday'), ('sat', 'Saturday')], default='sat', max_length=50)),
                ('work_week_hours', models.IntegerField(default=8)),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('opened', 'Opened'), ('paused', 'Paused'), ('closed', 'Closed')], default='pending', max_length=50)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('city', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.citiesmodel')),
                ('company', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.companydetailsmodel')),
                ('designation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.designationmodel')),
                ('industry', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.industriesmodel')),
            ],
        ),
        migrations.CreateModel(
            name='PlanPeriodModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('amount', models.IntegerField(default=0)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('period', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.periodmodel')),
                ('plan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.plansmodel')),
            ],
            options={
                'unique_together': {('plan', 'period')},
            },
        ),
        migrations.CreateModel(
            name='JobScreeningQuestionModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('answer', models.TextField(blank=True, default='', null=True)),
                ('type', models.CharField(choices=[('text', 'Text'), ('select', 'Select'), ('multi select', 'Multi select'), ('boolean', 'Boolean')], default='text', max_length=100, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('job', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.jobsmodel')),
                ('question', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.screeningquestionmodel')),
            ],
        ),
        migrations.CreateModel(
            name='JobRequriedSkillsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('requirement', models.CharField(choices=[('preferred', 'Preferred'), ('must have', 'Must have'), ('nice to have', 'Nice to have')], default='preferred', max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('job', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.jobsmodel')),
                ('skill', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.skillsmodel')),
            ],
        ),
        migrations.AddField(
            model_name='citiesmodel',
            name='state',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.statesmodel'),
        ),
        migrations.CreateModel(
            name='JobTagsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('job', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.jobsmodel')),
                ('tag', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.tagsmodel')),
            ],
        ),
        migrations.CreateModel(
            name='UserModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('email', models.EmailField(max_length=254, unique=True)),
                ('mobile', models.CharField(max_length=100)),
                ('photo', models.ImageField(blank=True, null=True, upload_to='profile_pic')),
                ('email_status', models.TextField(blank=True, default='', null=True)),
                ('mobile_status', models.TextField(blank=True, default='', null=True)),
                ('is_staff', models.BooleanField(default=False)),
                ('is_superuser', models.BooleanField(default=False)),
                ('is_company', models.BooleanField(default=False)),
                ('is_active', models.BooleanField(default=True)),
                ('otp', models.CharField(blank=True, default='', max_length=100, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('parent_user', models.ForeignKey(blank=True, default=None, null=True, on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
                ('role', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='auth.group')),
            ],
        ),
        migrations.CreateModel(
            name='UserEducationDetailsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('university_name', models.CharField(max_length=100)),
                ('institute_name', models.CharField(max_length=100)),
                ('specialization', models.CharField(blank=True, max_length=100, null=True)),
                ('course_type', models.CharField(max_length=100)),
                ('medium_of_education', models.CharField(max_length=100)),
                ('from_date', models.CharField(max_length=100)),
                ('to_date', models.CharField(blank=True, max_length=100, null=True)),
                ('cgpa', models.FloatField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
        ),
        migrations.CreateModel(
            name='UserDetailsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('gender', models.CharField(blank=True, max_length=10, null=True)),
                ('dob', models.DateField(blank=True, null=True)),
                ('current_address', models.TextField(blank=True, null=True)),
                ('permanent_address', models.TextField(blank=True, null=True)),
                ('notice_period', models.IntegerField(default=0)),
                ('annual_salary', models.FloatField(blank=True, null=True)),
                ('expected_salary', models.FloatField(blank=True, null=True)),
                ('married_status', models.CharField(blank=True, choices=[('single', 'Single'), ('married', 'Married'), ('divorced', 'Divorced'), ('widowed', 'Widowed'), ('others', 'Others')], default='', max_length=100, null=True)),
                ('negotiable', models.BooleanField(default=False)),
                ('resume', models.FileField(blank=True, null=True, upload_to='resume')),
                ('objective', models.TextField(blank=True, null=True)),
                ('workstatus', models.BooleanField(default=False)),
                ('experience', models.IntegerField(default=0)),
                ('is_disabled', models.BooleanField(default=False)),
                ('career_break', models.BooleanField(default=False)),
                ('break_duration_from', models.CharField(blank=True, default='', max_length=10, null=True)),
                ('break_duration_to', models.CharField(blank=True, default='', max_length=10, null=True)),
                ('break_reason', models.CharField(blank=True, default='', max_length=255, null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('current_city', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='living', to='hirework.citiesmodel')),
                ('designation', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='hirework.designationmodel')),
                ('industry', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='hirework.industriesmodel')),
                ('preferred_city', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, to='hirework.citiesmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
        ),
        migrations.CreateModel(
            name='UserCertificateModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('certificate_id', models.CharField(max_length=100)),
                ('name', models.CharField(max_length=100)),
                ('organization', models.CharField(max_length=100)),
                ('certified_date', models.DateField()),
                ('exp_date', models.DateField(blank=True, default=None, null=True)),
                ('certificate_link', models.CharField(blank=True, max_length=255, null=True)),
                ('cetificate_doc', models.FileField(blank=True, null=True, upload_to='certificates')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
        ),
        migrations.CreateModel(
            name='PlanPurchasedModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('transaction_id', models.CharField(max_length=100, unique=True)),
                ('status', models.IntegerField(default=1)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('plan_period', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.planperiodmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
        ),
        migrations.AddField(
            model_name='jobsmodel',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel'),
        ),
        migrations.AddField(
            model_name='companydetailsmodel',
            name='user',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel'),
        ),
        migrations.CreateModel(
            name='ChatsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('message', models.TextField()),
                ('status', models.BooleanField(default=False)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('receiver', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
                ('sender', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='sent', to='hirework.usermodel')),
            ],
        ),
        migrations.CreateModel(
            name='AnswersModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('answer', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('job_screening_question', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.jobscreeningquestionmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
        ),
        migrations.CreateModel(
            name='UserProfessionalDetailsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('organization', models.CharField(max_length=100)),
                ('worked_from', models.CharField(max_length=100)),
                ('worked_till', models.CharField(blank=True, max_length=100)),
                ('availability', models.BooleanField(default=False)),
                ('description', models.TextField(blank=True, default='', null=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('designation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.designationmodel')),
                ('industry', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.industriesmodel')),
                ('job_type', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.tagsmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
        ),
        migrations.CreateModel(
            name='UserProjectModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('description', models.TextField()),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('document', models.FileField(blank=True, default='', null=True, upload_to='projects')),
                ('document_link', models.CharField(blank=True, default='', max_length=255, null=True)),
                ('designation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.designationmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
        ),
        migrations.CreateModel(
            name='UserReasonModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('reason', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.breakreasonmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
        ),
        migrations.CreateModel(
            name='UserTokenModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.TextField(unique=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateField(auto_now=True)),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel', unique=True)),
            ],
        ),
        migrations.CreateModel(
            name='CompanyBenifitsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('benefit', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.benefitsmodel')),
                ('company', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.companydetailsmodel')),
            ],
            options={
                'unique_together': {('company', 'benefit')},
            },
        ),
        migrations.CreateModel(
            name='CompanySuplimentsModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('company', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.companydetailsmodel')),
                ('suppliment', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.supplimentalpaymodel')),
            ],
            options={
                'unique_together': {('company', 'suppliment')},
            },
        ),
        migrations.CreateModel(
            name='UserLanguageModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('read', models.BooleanField(default=False)),
                ('write', models.BooleanField(default=False)),
                ('speak', models.BooleanField(default=False)),
                ('proficiency', models.CharField(choices=[('beginner', 'Beginner'), ('intermediate', 'Intermediate'), ('advanced', 'Advanced'), ('fluent', 'Fluent')], default='beginner', max_length=100)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('language', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.languagemodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
            options={
                'unique_together': {('user', 'language')},
            },
        ),
        migrations.CreateModel(
            name='RecruiterDesignationPermissionModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('designation', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.designationmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
            options={
                'unique_together': {('user', 'designation')},
            },
        ),
        migrations.CreateModel(
            name='JobApplicationModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=100)),
                ('email', models.CharField(max_length=100)),
                ('mobile', models.CharField(max_length=100)),
                ('remarks', models.TextField(blank=True, null=True)),
                ('status', models.CharField(choices=[('reviewed', 'Reviewed'), ('pending', 'Pending'), ('shortlisted', 'Shortlisted'), ('interviewed', 'Interviewed'), ('rejected', 'Rejected'), ('selected', 'Selected')], default='reviewed', max_length=50)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('job', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.jobsmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
            options={
                'unique_together': {('user', 'job')},
            },
        ),
        migrations.CreateModel(
            name='FavoritesModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('job', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.jobsmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
            options={
                'unique_together': {('job', 'user')},
            },
        ),
        migrations.AlterUniqueTogether(
            name='companydetailsmodel',
            unique_together={('user', 'organization_email')},
        ),
        migrations.CreateModel(
            name='ProfessionalSkillModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('skill', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.skillsmodel')),
                ('job', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.userprofessionaldetailsmodel')),
            ],
            options={
                'unique_together': {('job', 'skill')},
            },
        ),
        migrations.CreateModel(
            name='ProjectSkillModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('skill', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.skillsmodel')),
                ('project', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.userprojectmodel')),
            ],
            options={
                'unique_together': {('project', 'skill')},
            },
        ),
        migrations.CreateModel(
            name='UserSkillModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('skill', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.skillsmodel')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='hirework.usermodel')),
            ],
            options={
                'unique_together': {('user', 'skill')},
            },
        ),
    ]
