from django.db import models
from django.contrib.auth.models import BaseUserManager, AbstractBaseUser, Group
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ValidationError
# Create your models here. admin@hirework.co.in -> Admin@123

#============================================================== Independents ==============================================================

class StatesModel(models.Model):
    state = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.state
    
class CitiesModel(models.Model):
    state = models.ForeignKey(StatesModel, on_delete=models.CASCADE)
    city = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.city

class IndustriesModel(models.Model):
    industry = models.CharField(max_length=100, unique=True)
    image = models.ImageField(upload_to="industries", null=True, default=None)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self) -> str:
        return self.industry

class SkillsModel(models.Model):
    skill = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.skill
    
class DesignationModel(models.Model):
    designation = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.designation

class TagsModel(models.Model):
    name = models.CharField(max_length=100,unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name
    
class BreakReasonModel(models.Model):
    name = models.CharField(max_length=100,unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name

class ScreeningQuestionModel(models.Model):
    question = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.question

class BenefitsModel(models.Model):
    benefit = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.benefit

class SupplimentalPayModel(models.Model):
    supplimentary = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.benefit
 
class LanguageModel(models.Model):
    language = models.CharField(max_length=100, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.language

#============================================================== Custom-User and Token ==============================================================
#Admin, Admin@123
class UserModel(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField(max_length=254, unique=True)
    password = models.TextField()
    role = models.ForeignKey(Group, on_delete=models.CASCADE, null=True, blank=True)
    mobile = models.CharField(max_length=100)
    photo = models.ImageField(upload_to="profile_pic", blank= True, null = True)
    email_status  = models.TextField(default="", blank=True, null=True)
    mobile_status  = models.TextField(default="", blank=True, null=True)
    is_staff  = models.BooleanField(default=False)
    is_superuser  = models.BooleanField(default=False)
    is_company  = models.BooleanField(default=False)
    parent_user = models.ForeignKey('self', on_delete=models.CASCADE, null=True, blank=True, default=None)
    is_active  = models.BooleanField(default=True)
    otp = models.CharField(max_length=100, blank= True, null = True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name
    
    def save(self, *args, **kwargs):
        if self.parent_user is not None:
            if self.parent_user == self:
                raise ValidationError("A user cannot be their own parent.")
            if self.parent_user.parent_user == self:
                raise ValidationError("A child cannot be a parent.")
        super().save(*args, **kwargs)

class UserTokenModel(models.Model):
    user = models.OneToOneField(UserModel, on_delete=models.CASCADE, unique=True)
    token = models.TextField(null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now= True)

    def __str__(self) -> str:
        return self.user.name

#============================================================== User-and-Details ==============================================================

class UserDetailsModel(models.Model):
    MARRIED_CHOICES = [
        ('single', 'Single'),
        ('married', 'Married'),
        ('divorced', 'Divorced'),
        ('widowed', 'Widowed'),
        ('others', 'Others'),
    ]

    SHIFT_TYPES = [
        ('day', 'Day Shift'),
        ('night', 'Night Shift'),
        ('evening', 'Evening Shift'),
        ('rotating', 'Rotating Shift'),
        ('weekend', 'Weekend Shift'),
    ]
        
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    designation = models.ForeignKey(DesignationModel,on_delete=models.CASCADE, null=True, blank=True)
    gender = models.CharField(max_length=10, null=True, blank=True)
    dob = models.DateField(null=True, blank=True)
    current_city = models.ForeignKey(CitiesModel,on_delete=models.CASCADE, related_name="living", null=True, blank=True)
    preferred_city = models.ForeignKey(CitiesModel,on_delete=models.CASCADE, null=True, blank=True)
    preferred_job_shift = models.CharField(choices=SHIFT_TYPES, max_length=20, default='day')
    current_address = models.TextField(null=True, blank=True) 
    permanent_address = models.TextField(null=True, blank=True)
    industry = models.ForeignKey(IndustriesModel,on_delete=models.CASCADE, null=True, blank=True)
    notice_period = models.IntegerField(default=0) #in days
    annual_salary = models.FloatField(null=True, blank=True)
    expected_salary = models.FloatField(null=True, blank=True)
    married_status = models.CharField(max_length=100, choices=MARRIED_CHOICES, blank=True, null=True, default="")    #enum
    negotiable = models.BooleanField(default=False)
    resume = models.FileField(upload_to="resume", null=True, blank=True)
    objective = models.TextField(null=True, blank=True) 
    workstatus = models.BooleanField(default=False) #fresher or not
    experience = models.IntegerField(default=0)
    is_disabled = models.BooleanField(default=False)
    career_break = models.BooleanField(default=False)
    break_duration_from = models.CharField(max_length=10,null=True, blank=True, default="")
    break_duration_to = models.CharField(max_length=10,null=True, blank=True, default="")
    break_reason = models.CharField(max_length=255, null=True, blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.user.name

class UserReasonModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    reason = models.ForeignKey(BreakReasonModel, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.reason.name  

class UserProfessionalDetailsModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    organization = models.CharField(max_length=100)
    designation = models.ForeignKey(DesignationModel, on_delete=models.CASCADE)
    industry = models.ForeignKey(IndustriesModel, on_delete=models.CASCADE)
    job_type = models.ForeignKey(TagsModel, on_delete=models.CASCADE)
    worked_from = models.CharField(max_length=100)
    worked_till = models.CharField(max_length=100, blank=True)
    availability = models.BooleanField(default=False)   #still working
    description = models.TextField(null=True, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.organization    

class UserCertificateModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    certificate_id = models.CharField(max_length=100)
    name = models.CharField(max_length=100)
    organization = models.CharField(max_length=100)
    certified_date = models.DateField()
    exp_date = models.DateField(null=True, blank=True, default=None)
    certificate_link = models.CharField(max_length=255, blank=True, null=True)
    cetificate_doc = models.FileField(upload_to="certificates", null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name

class UserSkillModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    skill = models.ForeignKey(SkillsModel, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    class Meta:
        unique_together = ('user', 'skill',)

    def __str__(self) -> str:
        return self.user.name  

class UserProjectModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    designation = models.ForeignKey(DesignationModel, on_delete=models.CASCADE)
    description = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    document = models.FileField(upload_to="projects", blank=True, null=True,  default = '')
    document_link = models.CharField(max_length=255, blank=True, null=True, default='')


    def __str__(self) -> str:
        return self.name  

class ProjectSkillModel(models.Model):
    project = models.ForeignKey(UserProjectModel, on_delete=models.CASCADE)
    skill = models.ForeignKey(SkillsModel, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        unique_together = ('project', 'skill',)

    def __str__(self) -> str:
        return self.project.name  
    
class ProfessionalSkillModel(models.Model):
    job = models.ForeignKey(UserProfessionalDetailsModel, on_delete=models.CASCADE)
    skill = models.ForeignKey(SkillsModel, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    class Meta:
        unique_together = ('job', 'skill',)

    def __str__(self) -> str:
        return self.job.organization

class UserEducationDetailsModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    university_name = models.CharField(max_length=100)
    institute_name = models.CharField(max_length=100)
    specialization = models.CharField(max_length=100, blank=True, null = True)
    course_type = models.CharField(max_length=100)
    medium_of_education = models.CharField(max_length=100)
    from_date = models.CharField(max_length=100)
    to_date = models.CharField(max_length=100, blank=True, null = True)
    cgpa = models.FloatField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.course_type  

class UserLanguageModel(models.Model):
    PROFICIENCY_CHOICE = [
        ('beginner', "Beginner"),
        ("intermediate","Intermediate"),
        ("advanced","Advanced"),
        ("fluent","Fluent"),
    ]
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    language = models.ForeignKey(LanguageModel, on_delete=models.CASCADE)
    read = models.BooleanField(default=False)
    write = models.BooleanField(default=False)
    speak = models.BooleanField(default=False)
    proficiency = models.CharField(max_length=100, choices=PROFICIENCY_CHOICE, default='beginner')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'language')

    def __str__(self) -> str:
        return self.language.language   

#============================================================== Recruiter-Details ==============================================================

class CompanyDetailsModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    industry = models.ForeignKey(IndustriesModel, on_delete=models.CASCADE)
    organization_name = models.CharField(max_length=255)
    organization_email = models.EmailField(unique=True)
    is_top = models.BooleanField(default=False)
    organization_mobile = models.CharField(max_length=100, blank=True, null=True)
    organization_description = models.TextField(blank=True, null=True)
    alternate_mobile = models.CharField(max_length=100, blank=True, null=True)
    organization_address = models.TextField(blank=True, null=True)
    organization_gst = models.CharField(max_length=100, null=True, blank=True, default="")
    organization_pan = models.CharField(max_length=100, null=True, blank=True, default="")
    organization_city = models.ForeignKey(CitiesModel, on_delete=models.CASCADE)
    organization_logo = models.ImageField(upload_to="logo", blank=True, null=True, default=None)
    organization_website = models.CharField(max_length=100, null=True, blank=True, default="")
    organization_fb = models.CharField(max_length=100, null=True, blank=True, default="")
    organization_insta = models.CharField(max_length=100, null=True, blank=True, default="")
    organization_ln = models.CharField(max_length=100, null=True, blank=True, default="")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'organization_email')

    def __str__(self) -> str:
        return self.organization_name
    
class CompanyBenifitsModel(models.Model):
    company = models.ForeignKey(CompanyDetailsModel, on_delete=models.CASCADE)
    benefit = models.ForeignKey(BenefitsModel, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('company', 'benefit')

    def __str__(self) -> str:
        return self.benefit

class CompanySuplimentsModel(models.Model):
    company = models.ForeignKey(CompanyDetailsModel, on_delete=models.CASCADE)
    suppliment = models.ForeignKey(SupplimentalPayModel, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('company', 'suppliment')

    def __str__(self) -> str:
        return self.suppliment

class RecruiterDesignationPermissionModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    designation = models.ForeignKey(DesignationModel, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('user', 'designation')

    def __str__(self) -> str:
        return self.user.name
 
#============================================================== Pricings-and-Plans ==============================================================

class PlansModel(models.Model):
    name = models.CharField(max_length=100,unique=True)
    plan_description = models.TextField(null=True, blank=True)
    job_posting_count = models.IntegerField(default=3)
    application_count = models.IntegerField(default=50)
    database_access_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name

class PeriodModel(models.Model):
    period = models.IntegerField(unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return str(self.period)

class PlanPeriodModel(models.Model):
    plan = models.ForeignKey(PlansModel,on_delete=models.CASCADE)
    period = models.ForeignKey(PeriodModel,on_delete=models.CASCADE)
    amount = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ('plan', 'period')

    def __str__(self) -> str:
        return f"{self.plan.name} -> {self.period.period}months -> {self.amount}"

class PlanPurchasedModel(models.Model):
    plan_period = models.ForeignKey(PlanPeriodModel, on_delete=models.CASCADE)
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    transaction_id = models.CharField(max_length=100, unique=True)
    status = models.IntegerField(default=1)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.transaction_id

#============================================================== Job-Postings ==============================================================

class JobsModel(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('opened', 'Opened'),
        ('paused', 'Paused'),
        ('closed', 'Closed'),
    ]

    SALARY_TYPE_CHOICES = [
        ('exact', 'Exact'),
        ('base', 'Base'),
        ('range', 'Range'),
    ]

    DAYS_OF_WEEK = [
        ('sun', 'Sunday'),
        ('mon', 'Monday'),
        ('tue', 'Tueday'),
        ('wed', 'Wednesday'),
        ('thur', 'Thursday'),
        ('fri', 'Friday'),
        ('sat', 'Saturday'),
    ]

    SHIFT_TYPES = [
        ('day', 'Day Shift'),
        ('night', 'Night Shift'),
        ('evening', 'Evening Shift'),
        ('rotating', 'Rotating Shift'),
        ('weekend', 'Weekend Shift'),
    ]

    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    company = models.ForeignKey(CompanyDetailsModel, on_delete=models.CASCADE)
    name = models.CharField(max_length=100,unique=True)
    description = models.TextField()
    city = models.ForeignKey(CitiesModel,on_delete=models.CASCADE)
    designation = models.ForeignKey(DesignationModel,on_delete=models.CASCADE)
    industry = models.ForeignKey(IndustriesModel,on_delete=models.CASCADE)
    hired_by = models.IntegerField(default=0)   #in days
    annual_salary_type = models.CharField(max_length=50, choices=SALARY_TYPE_CHOICES, default="exact")
    start_salary = models.FloatField(null=True, blank=True)
    end_salary = models.FloatField()
    job_shift = models.CharField(choices=SHIFT_TYPES, max_length=20, default='day')
    number_of_openings = models.IntegerField(default=0)
    experience_from = models.IntegerField(default=0)
    experience_to = models.IntegerField(default=0)
    show_salary = models.BooleanField(default=True)
    address = models.TextField()
    pincode = models.CharField(max_length=50, null=True, blank=True, default=None)
    landmark = models.CharField(max_length=100)
    work_week_start = models.CharField(choices=DAYS_OF_WEEK, max_length=50, default="mon")
    work_week_end = models.CharField(choices=DAYS_OF_WEEK, max_length=50, default="sat")
    work_week_hours = models.IntegerField(default=8)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES , default="pending")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name

class JobRequriedSkillsModel(models.Model):

    REQUIREMENT_CHOICE = [
        ("preferred","Preferred"),
        ("must have","Must have"),
        ("nice to have","Nice to have"),
    ]

    job = models.ForeignKey(JobsModel,on_delete=models.CASCADE)
    skill = models.ForeignKey(SkillsModel, on_delete=models.CASCADE)
    requirement = models.CharField(max_length=100, choices=REQUIREMENT_CHOICE, default="preferred")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.job.company.organization_name} -> {self.job.name} -> {self.skill.skill}"

class JobTagsModel(models.Model):
    job = models.ForeignKey(JobsModel,on_delete=models.CASCADE)
    tag = models.ForeignKey(TagsModel,on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return f"{self.job.company.organization_name} -> {self.job.name}-> {self.tag.name}"

class JobScreeningQuestionModel(models.Model):

    QUESTION_TYPES = [
        ("text","Text"),
        ("select","Select"),
        ("multi select","Multi select"),
        ("boolean","Boolean"),
    ]

    job = models.ForeignKey(JobsModel,on_delete=models.CASCADE)
    question = models.ForeignKey(ScreeningQuestionModel,on_delete=models.CASCADE)
    answer = models.TextField(null=True, blank=True, default="")
    type = models.CharField(max_length=100, choices=QUESTION_TYPES,null=True, default="text")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.question.question

#============================================================== Applications-Answers-Chats-Favorites ==============================================================

class JobApplicationModel(models.Model):
    APPLICATION_STATUS_CHOICES = [
        ('reviewed','Reviewed'),
        ('pending','Pending'),
        ('shortlisted','Shortlisted'),
        ('interviewed','Interviewed'),
        ('rejected','Rejected'),
        ('selected','Selected')
    ]
    name = models.CharField(max_length=100)
    email = models.CharField(max_length=100)
    mobile = models.CharField(max_length=100)

    job = models.ForeignKey(JobsModel, on_delete=models.CASCADE)
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    remarks = models.TextField(blank=True, null=True)
    status = models.CharField(max_length=50, choices=APPLICATION_STATUS_CHOICES, default="reviewed") #0,1,2,3,4,5 pending reviewed shortlisted interviewed rejected selected 

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ("user", "job")

    def __str__(self) -> str:
        return f"{self.user.name} => {self.job.name} => {self.job.company.organization_name}"

class AnswersModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    job_screening_question = models.ForeignKey(JobScreeningQuestionModel, on_delete=models.CASCADE)
    answer = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.answer
    
class ChatsModel(models.Model):
    sender = models.ForeignKey(UserModel, on_delete=models.CASCADE, related_name="sent")
    receiver = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    message = models.TextField()
    status = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return self.message
    
class FavoritesModel(models.Model):
    job = models.ForeignKey(JobsModel, on_delete=models.CASCADE)
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("job", "user")

    def __str__(self) -> str:
        return self.user.name

    
class NotificationsModel(models.Model):
    user = models.ForeignKey(UserModel, on_delete=models.CASCADE)
    message = models.TextField()
    description = models.TextField(default='')
    status = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.user.name} => {self.message}"


class LogsModel(models.Model):
    api = models.CharField(max_length=150)
    method = models.CharField(max_length=100)
    error = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self) -> str:
        return f"{self.api} => {self.method}"