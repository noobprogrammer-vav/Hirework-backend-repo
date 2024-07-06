from .views import *
from django.urls import path

urlpatterns = [
    path("tester/", tester),
    path("readlogs/", GetLogView),

    path("signup/", SignupView),
    path("login/", LoginView),
    path("logout/", LogoutView),
    path("verifyotp/", OtpView),
    path("forgotpassword/", ForgotView),
    path("regenotp/", ReotpView),
    path("pwdchange/",ChangePwdView),

    path("profileors/", UserResumeView),
    path("userbasicdetails/", UserBasicView),
    path("myprofile/", UserDetailsView.as_view()),
    path("usereducation/", UserEducationView.as_view()),
    path("useremployment/", UserEmploymentView.as_view()),
    path("userproject/", UserProjectView.as_view()),
    path("userlanguage/", UserLanguageView.as_view()),

    path("states/", StatesView.as_view()),
    path("cities/", CityView.as_view()),
    path("industries/", IndustriesView.as_view()),
    path("skills/", SkillsView.as_view()),
    path("designation/", DesignationView.as_view()),
    path("tags/", TagsView.as_view()),
    path("language/", LanguageView.as_view()),
    path("breakreason/", BreakReasonView.as_view()),
    path("screeningqs/", ScreeningQuestionView.as_view()),
    path("benefits/", BenefitsView.as_view()),
    path("supplimentals/", SupplimentalView.as_view()),


    path("jobs/", JobsView.as_view()),
    path("apply_job/", JobApplicationView.as_view()),
    path("favorites/",FavoritesView.as_view()),


    path("recruiter/",RecruiterActions.as_view()),

    path("companydetails/", CompanyDetailsView.as_view()),

    path('permissions/', PermissionsView.as_view()),
]