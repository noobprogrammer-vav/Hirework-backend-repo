from rest_framework import serializers
from .models import *

#========================================================== User Details -> User-POV ==========================================================

class UserProfessionalGetSerializer(serializers.ModelSerializer):
    industry = serializers.CharField(source='industry.industry', read_only=True)
    designation = serializers.CharField(source='designation.designation', read_only=True)
    job_type = serializers.CharField(source='job_type.name', read_only=True)
    class Meta:
        model = UserProfessionalDetailsModel
        fields = ["id","organization", "designation", "industry", "job_type", "worked_from", "worked_till", "availability", "description"]

class UserDetailPostSerialiser(serializers.ModelSerializer):
    class Meta:
        model = UserDetailsModel
        fields = ['user', 'designation', 'annual_salary', 'workstatus', 'notice_period', 'experience']

class UserProfilePostSerialiser(serializers.ModelSerializer):
    class Meta:
        model = UserModel
        fields = ["email", "mobile", "name"]

class UserDetailPostSerialiser2(serializers.ModelSerializer):
    class Meta:
        model = UserDetailsModel
        fields = ["user",'career_break', "current_city", "preferred_city", "current_address", "permanent_address", "gender", "dob", "industry", "expected_salary", "married_status", "negotiable", "is_disabled", "break_duration_from", "break_duration_to", "break_reason"]

class UserEducationSerialiser(serializers.ModelSerializer):
    class Meta:
        model = UserEducationDetailsModel
        fields = ["user", "university_name", "institute_name", "specialization", "course_type", "medium_of_education", "from_date", "to_date", "cgpa"]

class UserEmploymentSerialiser(serializers.ModelSerializer):
    class Meta:
        model = UserProfessionalDetailsModel
        fields = ["user", "organization", "designation", "industry", "job_type", "worked_from", "worked_till", "availability", "description"]

class UserProjectSerialiser(serializers.ModelSerializer):
    class Meta:
        model = UserProjectModel
        fields = ['name', 'designation', 'description', 'document', 'document_link', 'user']

class UserLanguageSerialser(serializers.ModelSerializer):
    class Meta:
        model = UserLanguageModel
        fields = ["user", "language", "read", "write", "speak", "proficiency"]

#========================================================== Recruiter - Company ==========================================================

class CompanyPostSerializer(serializers.ModelSerializer):
    class Meta:
        model = CompanyDetailsModel
        fields = ["user", "industry", "organization_name", "organization_email", "is_top", "organization_mobile", "alternate_mobile", "organization_address", "organization_gst", "organization_pan", "organization_city", "organization_logo", "organization_website", "organization_fb", "organization_insta", "organization_ln"]

#========================================================== Jobs ==========================================================

class JobPostSerialiser(serializers.ModelSerializer):
    class Meta:
        model = JobsModel
        fields = ["user", "company", "name", "description", "city", "designation", "industry", "hired_by", "annual_salary_type", "start_salary", "end_salary", "number_of_openings", "experience_from", "experience_to", "show_salary", "address", "pincode", "landmark", "work_week_start", "work_week_end", "work_week_hours", ]