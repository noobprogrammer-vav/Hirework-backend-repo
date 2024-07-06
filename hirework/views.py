from django.shortcuts import render, get_object_or_404
from django.contrib.auth import authenticate, logout, login

from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.middleware.csrf import get_token

from django.contrib.auth.models import Permission
from django.forms.models import model_to_dict
from django.db.models import Q
from django.utils import timezone
from dateutil.relativedelta import relativedelta

from rest_framework.permissions import AllowAny, SAFE_METHODS, IsAdminUser
from rest_framework.decorators import api_view, APIView, permission_classes
from rest_framework.response import Response
from rest_framework import status

from .permissions import *
from .serializer import *
from .models import *

import math, random, logging, os, jwt, datetime, hashlib
from dotenv import load_dotenv
load_dotenv()
SECRET_KEY = os.environ.get('SECRET_KEY')
logger = logging.getLogger(__name__)

# Create your views here.

def Header_Checker(request):
    the_token = request.headers.get("Authorization")
    if(the_token is not None):
        the_token = the_token.replace("Bearer ",'')
        try:
            decoded_token = jwt.decode(the_token, SECRET_KEY, algorithms=["HS256"])
            difference = datetime.datetime.now() - datetime.datetime.strptime(decoded_token.get("login_time"), '%Y-%m-%d %H:%M:%S.%f')
            if(difference.total_seconds() > 3600):
                return False
            else:
                return decoded_token
        except Exception as e:
            logger.error(f'Error in OtpView_ from POST method : {str(e)}')
            return False
    return False

#========================================================== Internal Functions ==========================================================

def tokenizer(user_id, staff, company, parent):
    return jwt.encode({'user_id': user_id, "login_time" : str(datetime.datetime.now()), "is_staff" : staff, "is_company" : company, "parent_user" : parent}, SECRET_KEY, algorithm="HS256")

def token_decoder(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception as e:
        return str(e)

def login_function(request):
    the_user = get_object_or_404(UserModel, email = request.data.get("email"), password = hashlib.sha256(request.data.get("password").encode("utf-8")).hexdigest() )
    the_token_model = the_user.usertokenmodel # this is for onetoonefield, for foreignkey we use "usertokenmodel_set()"
    the_parent = False
    if the_user.parent_user is not None:
        the_parent = True
    the_token = tokenizer(the_user.pk, the_user.is_staff, the_user.is_company, the_parent)
    the_token_model.token = the_token
    the_token_model.save()
    return [the_user, the_token]

# to check whether the token is expired or not and return the user model
def authenticator(request):
    the_token = request.headers.get("Authorization")
    if(the_token is None):
        return False
    the_token = the_token.replace("Bearer ",'')
    the_token = get_object_or_404(UserTokenModel, token = the_token)
    the_user = the_token.user
    difference = timezone.now() - the_token.updated_at
    if difference.days > 1 or (difference.seconds / (3600)) >= 3.0 :
        return False
    else:
        return the_user


def serialiser_errors(serials):
    all_errors = []
    for serial in serials:
        if(serial.is_valid()):
            pass
        else:
            for error in serial.errors.keys():
                all_errors.append({
                    "field" : error,
                    "message" : serial.errors.get(error)[0]
                })
    return all_errors

def otp_generator(): 
    OTP = ""
    for i in range(4) :
        OTP += str(math.floor(random.random() * 10))

    hashed_otp = jwt.encode({"otp" : OTP, "gen_time" : str(datetime.datetime.now())}, SECRET_KEY, algorithm="HS256")
    # hashed_otp = hashlib.sha256(OTP.encode("utf-8")).hexdigest()
    logger.info(f'OTP is {OTP} ')
    return hashed_otp

# def user_checker(user_id):
#     user = get_object_or_404(UserModel, pk= user_id)
#     return user

def user_plan_checker(the_model):

    difference = (the_model.updated_at + relativedelta(months=the_model.plan_period.period.period) - relativedelta(days=2)) - timezone.now()
    remaining_time = {
        "years" : difference.days // 365,
        "months" : (difference.days % 365) // 30,
        "days" : difference.days % 30,
        "hours" : difference.seconds // 3600,
        "minutes" : (difference.seconds % 3600) // 60,
        "seconds" : difference.seconds % 60,
    }
    # years = difference.days // 365
    # months = (difference.days % 365) // 30
    # days = difference.days % 30
    # hours = difference.seconds // 3600
    # minutes = (difference.seconds % 3600) // 60
    # seconds = difference.seconds % 60

    result = {
    "job_limit" : the_model.plan_period.plan.job_posting_count,
    "application_limit" : the_model.plan_period.plan.application_count,
    "database_limit" : the_model.plan_period.plan.database_access_count,
    "amount" : the_model.plan_period.amount,
    "plan_period" : the_model.plan_period.period.period,
    "plan_purchased_date" : the_model.updated_at,
    "plan_end_date" : the_model.updated_at + relativedelta(months=the_model.plan_period.period.period),
    "remaining_time" : remaining_time,
    }

    return result

def handle_exceptions(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f'Error occurred: {str(e)}')
            return Response({
                "status": "error",
                "code": "500",
                "message": str(e),
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    return wrapper
#========================================================== Comments-tests ==========================================================

@api_view(["GET"])
@permission_classes([CustomIsAdmin])
def tester(request):

    my_test = Header_Checker(request)
    # print(my_test.get("is_staff"), type(my_test.get("is_staff")))

    return Response({"status" : my_test })

# else:
#     #print(serialiser.errors)
#     return Response(
#         {
#         "status" : "error" , 
#         "code" : "400", 
#         "message" : "Signup failed", 
#         "data" : { 
#             "errors" : serialiser_errors(serialiser)
#             }
#         },status=status.HTTP_400_BAD_REQUEST)


    # def post(self,request):
    #     logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
    #     try:
    #         return Response({
    #             "status" : "success",
    #             "code" : "200",
    #             "message" : "OK",
    #             "data" : data
    #         }, status=status.HTTP_200_OK)
    #     except Exception as e:
    #         logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
    #         return Response(
    #             {
    #             "status" : "error" , 
    #             "code" : "500", 
    #             "message" : str(e), 
    #             },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
# logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')

#========================================================== GET-LOGS ==========================================================

@api_view(["GET"])
@permission_classes([IsAdminUser])
def GetLogView(request):
    logger.info(f'Reqest for GetLogView_ using GET method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
    
    log_path = "hirework_django_logs/info_logs.txt"
    if(request.query_params.get("type") == "error"):
        log_path = "hirework_django_logs/error_logs.txt"
    if os.path.exists(log_path):
        log_content = []
        with open(log_path, 'r') as log_file:
            for line in log_file:
                log_content.append(line.strip())
        
        return Response({"Logs" : log_content})
    else:
        logger.error(f'Error in GetLogView_ from GET method : Log file not found')
        return Response({'message': 'Log file not found'}, status=status.HTTP_404_NOT_FOUND)

#========================================================== Roles-and-Permissions ==========================================================

class PermissionsView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [CustomIsAuthenticated()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        if(request.query_params.get("all") == "1"):
            all_permissions = Permission.objects.all().values_list("id", "name", "codename")
        elif(request.query_params.get("uid") is not None):
            all_permissions = get_object_or_404(UserModel, pk = request.query_params.get("uid")).role.permissions.all().values("id", "name", "codename")
        else:
            verified = authenticator(request)
            if(verified is False):
                return Response({"message" : "Invalid Token"}, status=status.HTTP_401_UNAUTHORIZED)
            if(verified.role):
                all_permissions = verified.role.permissions.all().values("id", "name", "codename")
            else:
                all_permissions = []
        return Response({
            "status" : "success" , 
            "code" : "200", 
            "message" : "OK", 
            "data" : {
                "permissions" : all_permissions,
            }
            },status=status.HTTP_200_OK)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if not request.data.get("name") or not request.data.get("permissions"):
                raise Exception("Name or Permissions missing")
            the_role = Group.objects.create(name = request.data.get("name"))
            the_role.permissions.set(request.data.get("permissions"))
            the_role.save()

            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
            },status=status.HTTP_201_CREATED) 
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response({
                "status" : "error" , 
                "code" : "400", 
                "message" : "Invalid Data", 
                "data" : { 
                    "errors" : [
                        { "field" : "name or permissions", "message" : "name or permissions field is missing" }
                    ] 
                } },status=status.HTTP_400_BAD_REQUEST) 

    def put(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if not request.data.get("role") or not request.data.get("permissions"):
                raise Exception("Missing Role_id or Permissions")
            the_role = get_object_or_404(Group, pk = request.data.get("role"))

            the_role.permissions.set(request.data.get("permissions"))
            the_role.save()

            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
            },status=status.HTTP_201_CREATED) 
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response({
                "status" : "error" , 
                "code" : "400", 
                "message" : "Invalid Data", 
                "data" : { 
                    "errors" : [
                        { "field" : "role or permissions", "message" : "role or permissions field is missing" }
                    ] 
                } },status=status.HTTP_400_BAD_REQUEST)

#========================================================== Signup-Login-Logout-OTP-PWD ==========================================================

#Over
@api_view(["POST"])
def SignupView(request):
    try:
        logger.info(f'Reqest for SignupView_ using POST method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        
        required_fields = ["name", "email", "mobile", "password", "company"]
        for the_field in required_fields:
            if(request.data.get(the_field) is None):
                raise Exception(f"{the_field} field cannot be null")
            if(the_field == "company"):
                if(request.data.get("company") == "True"):
                    required_fields.extend(["organization_name", "organization_industry", "organization_email", "organization_city"])
            
        the_password = hashlib.sha256(request.data.get("password").encode("utf-8")).hexdigest()
        the_user = UserModel.objects.create(name = request.data.get("name"), email = request.data.get("email"), password = the_password, mobile = request.data.get("mobile"), is_company = request.data.get("company"))
        the_user.email_status = otp_generator()
        the_user.mobile_status = otp_generator()
        the_user.save()
        the_parent = False
        if the_user.parent_user is not None:
            the_parent = True
        the_token = tokenizer(the_user.pk, the_user.is_staff, the_user.is_company, the_parent)
        UserTokenModel.objects.create(user = the_user, token = the_token)
        # login(request=request, user=the_user)
        if (the_user.is_company == "True"):
            plan = PlanPeriodModel.objects.get(amount=0)
            PlanPurchasedModel.objects.create(plan_period = plan, user = the_user, transaction_id = f"free:{datetime.datetime.now()}")
            the_city = get_object_or_404(CitiesModel, pk = request.data.get("organization_city"))
            the_industry = get_object_or_404(IndustriesModel, pk = request.data.get("organization_industry"))
            CompanyDetailsModel.objects.create(user = the_user, organization_name = request.data.get("organization_name"), organization_email = request.data.get("organization_email"), organization_city = the_city, industry = the_industry)
        return Response(
            {
            "status" : "success" , 
            "code" : "201", 
            "message" : "Signup Successful", 
            "token" : the_token
            },status=status.HTTP_201_CREATED)
    except Exception as e:
        logger.error(f'Error in SignupView_ from POST method : {str(e)}')
        return Response(
            {
            "status" : "error" , 
            "code" : "400", 
            "message" : "Signup failed", 
            "data" : { 
                "errors" : str(e)
                }
            },status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
def OtpView(request):
    try:
        logger.info(f'Reqest for OtpView_ using POST method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        if(request.query_params.get("fp") is not None):
            required_fields = ["otp", "password", "email"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise Exception(f"{the_field} field cannot be null")
            
            the_user = get_object_or_404(UserModel, email = request.data.get("email"))
            if(the_user.otp is None or the_user.otp == ''):
                raise Exception("OTP was never generated")
            user_otp = jwt.decode(the_user.otp, SECRET_KEY, algorithms=["HS256"])
            difference = datetime.datetime.now() - datetime.datetime.strptime(user_otp.get("gen_time"), '%Y-%m-%d %H:%M:%S.%f')
            if((difference.total_seconds() / 3600) > 3):
                raise Exception("OTP expired")
            
            if(user_otp.get("otp") != request.data.get("otp")):
                raise Exception("Invalid Otp")

            the_user.otp = ''
            the_user.password = hashlib.sha256(request.data.get("password").encode("utf-8")).hexdigest()
            the_user.save()
            
        else:
            required_fields = ["email_otp", "mobile_otp"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise Exception(f"{the_field} field cannot be null")
            
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentials were not provided")
            if(verified_user.email_status == ""):
                return Response(
                    {
                    "status" : "success" , 
                    "code" : "208", 
                    "message" : "OTP verified Already", 
                    },status=status.HTTP_208_ALREADY_REPORTED)
            
            user_email = jwt.decode(verified_user.email_status, SECRET_KEY, algorithms=["HS256"])
            user_mobile = jwt.decode(verified_user.mobile_status, SECRET_KEY, algorithms=["HS256"])

            difference = datetime.datetime.now() - datetime.datetime.strptime(user_email.get("gen_time"), '%Y-%m-%d %H:%M:%S.%f')

            if((difference.total_seconds() / 3600) > 3):
                raise Exception("OTP expired")

            if(user_email.get("otp") != request.data.get("email_otp") or user_mobile.get("otp") != request.data.get("mobile_otp")):
                raise Exception("Provided OTPs are Invalid")
            
            
            verified_user.email_status = ""
            verified_user.mobile_status = ""
            verified_user.save()

        return Response(
            {
            "status" : "success" , 
            "code" : "202", 
            "message" : "Verification Successful", 
            },status=status.HTTP_202_ACCEPTED)

    except Exception as e:
        logger.error(f'Error in OtpView_ from POST method : {str(e)}')
        return Response(
            {
            "status" : "error" , 
            "code" : "400", 
            "message" : "Verification failed", 
            "data" : { 
                "errors" : str(e)
                }
            },status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes([CustomIsAuthenticated])
def ReotpView(request):
    try:
        logger.info(f'Reqest for ReotpView_ using POST method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        verified_user = authenticator(request)
        if(verified_user.email_status == None or verified_user.email_status == ''):
            raise Exception("OTPs already Verified")
        verified_user.email_status = otp_generator()
        verified_user.mobile_status = otp_generator()
        verified_user.save()

        return Response(
            {
            "status" : "success" , 
            "code" : "201", 
            "message" : "OTPs regeneration Successful", 
            },status=status.HTTP_201_CREATED)
    except Exception as e:
        logger.error(f'Error in ReotpView_ from POST method : {str(e)}')
        return Response(
            {
            "status" : "error" , 
            "code" : "400", 
            "message" : "OTP generation failed", 
            "data" : { 
                "errors" : str(e)
                }
            },status=status.HTTP_400_BAD_REQUEST)

#Over
@api_view(["POST"])
def LoginView(request):
    logger.info(f'Reqest for LoginView_ using POST method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
    try:
        if not request.data.get("email") or not request.data.get("password"):
            raise ValueError("Email or Password not present")
        
        login_function_val = login_function(request)      
        the_user = login_function_val[0]

        if(the_user.email_status == '' or the_user.email_status == None):

            response =  Response({
                "status" : "success" , 
                "code" : "202", 
                "message" : "Login Successful",
                "token" : login_function_val[1],
                "resume" : the_user.userdetailsmodel_set.first().resume.name if the_user.userdetailsmodel_set.first() is not None else '',
            },status=status.HTTP_202_ACCEPTED)
            response.set_cookie('csrftoken',)
            return response
        else:
            return Response({
                "status" : "success" , 
                "code" : "202", 
                "message" : "Login Successful",
                "warning" : "Otps not verified",
                "token" : login_function_val[1],
                "resume" : the_user.userdetailsmodel_set.first().resume.name if the_user.userdetailsmodel_set.first() is not None else '',
            },status=status.HTTP_202_ACCEPTED)
    
    except ValueError as v:
        logger.error(f'Error in LoginView_ from POST method : {str(v)}')
        return Response({
            "status" : "error" , 
            "code" : "400", 
            "message" : "Invalid Data", 
            "data" : { 
                "errors" : [
                    { "field" : "Email or Password", "message" : "Email or Password field is missing" }
                ] 
            } },status=status.HTTP_400_BAD_REQUEST)
    
    except Exception as e:
        logger.error(f'Error in LoginView_ from POST method : {str(e)}')
        return Response({
            "status" : "error" , 
            "code" : "401", 
            "message" : "Invalid Credentials", 
            "data" : { 
                "errors" : str(e)
            } },status=status.HTTP_401_UNAUTHORIZED)

#Over
@api_view(["POST"])
def LogoutView(request):
    logger.info(f'Reqest for LogoutView_ using POST method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
    try:
        the_token = request.headers.get("Authorization")
        if(the_token == None):
            raise Exception("Authentication credentials were not provided")
        the_token = the_token.replace("Bearer ",'')
        UserTokenModel.objects.filter(token = the_token).update(token = None)
        return Response({
            "status" : "success" , 
            "code" : "202", 
            "message" : "Logout Successful", 
        },status=status.HTTP_200_OK)
    except Exception as e:
        logger.error(f'Error in LogoutView_ from POST method : {str(e)}')
        return Response({
            "status" : "error" ,
            "code" : "401",
            "message" : "Invalid Credentials",
            "data" : {
                "errors" : str(e)
                }
                },status=status.HTTP_401_UNAUTHORIZED)
    

#Over
@api_view(["POST"])
def ForgotView(request):
    try:
        logger.info(f'Reqest for ForgotView_ using POST method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        if request.data.get("email") is None:
            raise Exception("email field cannot be null")
        the_user = get_object_or_404(UserModel, email = request.data.get("email"))
        the_user.otp = otp_generator()
        the_user.save()
        return Response(
            {
            "status" : "success" , 
            "code" : "201", 
            "message" : "OTP Generated Successfully", 
            },status=status.HTTP_201_CREATED)
    except Exception as e :
        logger.error(f'Error in ForgotView_ from POST method : {str(e)}')
        return Response(
            {
            "status" : "error" , 
            "code" : "400", 
            "message" : "OTP Generation Failed", 
            "data" : { 
                "errors" : str(e)
                }
            },status=status.HTTP_400_BAD_REQUEST)

@api_view(["POST"])
@permission_classes([CustomIsAuthenticated])
def ChangePwdView(request):
    try:
        logger.info(f'Reqest for ChangePwdView_ using POST method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        required_fields = ["old_password", "password"]
        for the_field in required_fields:
            if request.data.get(the_field) is None:
                raise Exception(f"{the_field} field cannot be null")
        
        verified_user = authenticator(request)

        if(verified_user.password != hashlib.sha256(request.data.get("old_password").encode("utf-8")).hexdigest()):
            raise Exception("Password Incorrect")

        verified_user.password = hashlib.sha256(request.data.get("password").encode("utf-8")).hexdigest()
        verified_user.save()
        return Response(
            {
            "status" : "success" , 
            "code" : "201", 
            "message" : "Updated Successfully", 
            },status=status.HTTP_201_CREATED)
    except Exception as e:
        logger.error(f'Error in ChangePwdView_ from POST method : {str(e)}')
        return Response(
            {
            "status" : "error" , 
            "code" : "400", 
            "message" : "Password Updation Failed", 
            "data" : { 
                "errors" : str(e)
                }
            },status=status.HTTP_400_BAD_REQUEST)

#========================================================== Independents ==========================================================

class StatesView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            states = StatesModel.objects.all()
            if request.query_params.get("start") is not None:
                states = states.filter(Q(state__startswith = request.query_params.get("start").replace(" ","_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "states" : list(map(lambda x: {"id":x[0],"name" : x[1].replace("_", " ").title()},states.values_list("id", "state"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("state") is None:
                raise ValueError("state field cannot be null")
            
            the_name = request.data.get("state")
            the_name = the_name.lower().replace(" ","_")
                        
            StatesModel.objects.create(state = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "state",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["state", "state_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
            the_state = get_object_or_404(StatesModel, pk = request.data.get("state_id"))
            the_name = request.data.get("state")
            the_name = the_name.lower().replace(" ","_")
            the_state.state = the_name
            the_state.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "state_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("state_id") is None:
                raise ValueError("state_id cannot be null")

            get_object_or_404(StatesModel, pk = request.query_params.get("state_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "state_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class CityView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            city = CitiesModel.objects.all()
            if request.query_params.get("start") is not None:
                city = city.filter(Q(city__startswith = request.query_params.get("start").replace(" ", "_")))
            if request.query_params.get("state") is not None:
                city = city.filter(state = request.query_params.get("state").replace(" ", "_"))
    
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "cities" : list(map(lambda x: {"id":x[0], "name" : x[1].replace("_", " ").title(), "state_name" : x[2].replace("_"," ").title()},city.values_list("id", "city", "state__state"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            required_fields = ["city", "state_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
                
            the_name = request.data.get("city")
            the_name = the_name.lower().replace(" ","_")
                        
            CitiesModel.objects.create(state = request.data.get("state_id"), city = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "state",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["city_id", "city", "state_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
                
            the_city = get_object_or_404(CitiesModel, pk = request.data.get("city_id"))

            the_name = request.data.get("city")
            the_name = the_name.lower().replace(" ","_")

            the_city.state = request.data.get("state_id")
            the_city.city = the_name
            the_city.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : str(v).split(' ')[0],
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("city_id") is None:
                raise ValueError("city_id cannot be null")

            get_object_or_404(CitiesModel, pk = request.query_params.get("city_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "city_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class IndustriesView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            industries = IndustriesModel.objects.all()
            if request.query_params.get("start") is not None:
                industries = industries.filter(Q(industry__startswith = request.query_params.get("start").replace(" ","_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "industries" : list(map(lambda x: {"id":x[0],"name": x[1].replace("_", " ").title()},industries.values_list("id", "industry","image"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("industry") is None:
                raise ValueError("industry field cannot be null")
            if request.data.get("image") is None:
                raise ValueError("image field cannot be null")

            the_name = request.data.get("industry")
            the_name = the_name.lower().replace(" ","_")

            IndustriesModel.objects.create(industry = the_name, image=request.data.get("image"))
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "industry",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["industry", "industry_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
            the_industry = get_object_or_404(IndustriesModel, pk = request.data.get("industry_id"))

            the_name = request.data.get("industry")
            the_name = the_name.lower().replace(" ","_")

            the_industry.industry = the_name
            if(request.data.get("image") is not None):
                the_industry.image = request.data.get("image")
            the_industry.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "industry_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("industry_id") is None:
                raise ValueError("industry_id cannot be null")

            get_object_or_404(StatesModel, pk = request.query_params.get("industry_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "industry_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SkillsView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            skills = SkillsModel.objects.all()
            if request.query_params.get("start") is not None:
                skills = skills.filter(Q(skill__startswith = request.query_params.get("start").replace(" ","_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "skills" : list(map(lambda x: {"id":x[0], "name" : x[1].replace("_", " ").title()},skills.values_list("id", "skill"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("skill") is None:
                raise ValueError("skill field cannot be null")

            the_name = request.data.get("skill")
            the_name = the_name.lower().replace(" ","_")

            SkillsModel.objects.create(skill = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "skill",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["skill", "skill_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
            the_skill = get_object_or_404(SkillsModel, pk = request.data.get("skill_id"))

            the_name = request.data.get("skill")
            the_name = the_name.lower().replace(" ","_")

            the_skill.skill = the_name
            the_skill.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "skill_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("skill_id") is None:
                raise ValueError("skill_id cannot be null")

            get_object_or_404(SkillsModel, pk = request.query_params.get("skill_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "skill_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DesignationView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            designations = DesignationModel.objects.all()
            if request.query_params.get("start") is not None:
                designations = designations.filter(Q(designation__startswith = request.query_params.get("start").replace(" ","_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "designation" : list(map(lambda x: {"id":x[0],"name": x[1].replace("_", " ").title()},designations.values_list("id", "designation"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("designation") is None:
                raise ValueError("designation field cannot be null")

            the_name = request.data.get("designation")
            the_name = the_name.lower().replace(" ","_")

            DesignationModel.objects.create(designation = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "designation",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["designation", "designation_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
            the_designation = get_object_or_404(DesignationModel, pk = request.data.get("designation_id"))

            the_name = request.data.get("designation")
            the_name = the_name.lower().replace(" ","_")

            the_designation.designation = the_name
            the_designation.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "designation_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("designation_id") is None:
                raise ValueError("designation_id cannot be null")

            get_object_or_404(DesignationModel, pk = request.query_params.get("designation_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "designation_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class TagsView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            tags = TagsModel.objects.all()
            if request.query_params.get("start") is not None:
                tags = tags.filter(Q(name__startswith = request.query_params.get("start").replace(" ","_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "tags" : list(map(lambda x: {"id":x[0],"name": x[1].replace("_", " ").title()},tags.values_list("id", "name"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("name") is None:
                raise ValueError("name field cannot be null")

            the_name = request.data.get("name")
            the_name = the_name.lower().replace(" ","_")

            TagsModel.objects.create(name = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "name",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["name", "tag_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
            the_tag = get_object_or_404(TagsModel, pk = request.data.get("tag_id"))

            the_name = request.data.get("name")
            the_name = the_name.lower().replace(" ","_")

            the_tag.name = the_name
            the_tag.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "tag_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("tag_id") is None:
                raise ValueError("tag_id cannot be null")

            get_object_or_404(TagsModel, pk = request.query_params.get("tag_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "tag_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LanguageView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            languages = LanguageModel.objects.all()
            if request.query_params.get("start") is not None:
                languages = languages.filter(Q(language__startswith = request.query_params.get("start").replace(" ","_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "languages" : list(map(lambda x: {"id":x[0],"name": x[1].replace("_", " ").title()},languages.values_list("id", "language"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("language") is None:
                raise ValueError("language field cannot be null")

            the_name = request.data.get("language")
            the_name = the_name.lower().replace(" ","_")

            LanguageModel.objects.create(language = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "language",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["language", "language_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
            the_language = get_object_or_404(LanguageModel, pk = request.data.get("language_id"))

            the_name = request.data.get("language")
            the_name = the_name.lower().replace(" ","_")

            the_language.language = the_name
            the_language.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "language_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("language_id") is None:
                raise ValueError("language_id cannot be null")

            get_object_or_404(LanguageModel, pk = request.query_params.get("language_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "language_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
class BreakReasonView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            reasons = BreakReasonModel.objects.all()
            if request.query_params.get("start") is not None:
                reasons = reasons.filter(Q(name__startswith = request.query_params.get("start").replace(" ","_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "reasons" : list(map(lambda x: {"id":x[0],"name": x[1].replace("_", " ").title()},reasons.values_list("id", "name"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("reason") is None:
                raise ValueError("reason field cannot be null")

            the_name = request.data.get("reason")
            the_name = the_name.lower().replace(" ","_")

            BreakReasonModel.objects.create(name = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "reason",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["reason", "reason_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
            the_reason = get_object_or_404(BreakReasonModel, pk = request.data.get("reason_id"))

            the_name = request.data.get("reason")
            the_name = the_name.lower().replace(" ","_")

            the_reason.name = the_name
            the_reason.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "reason_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("reason_id") is None:
                raise ValueError("reason_id cannot be null")

            get_object_or_404(BreakReasonModel, pk = request.query_params.get("reason_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "reason_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class ScreeningQuestionView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            questions = ScreeningQuestionModel.objects.all()
            if request.query_params.get("start") is not None:
                questions = questions.filter(Q(question__startswith = request.query_params.get("start").replace(" ","_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "questions" : list(map(lambda x: {"id":x[0],"question": x[1].replace("_", " ").title()},questions.values_list("id", "question"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("question") is None:
                raise ValueError("question field cannot be null")

            the_name = request.data.get("question")
            the_name = the_name.lower().replace(" ","_")

            ScreeningQuestionModel.objects.create(question = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "question",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["question", "question_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
            the_question = get_object_or_404(ScreeningQuestionModel, pk = request.data.get("question_id"))

            the_name = request.data.get("question")
            the_name = the_name.lower().replace(" ","_")

            the_question.question = the_name
            the_question.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "question_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("question_id") is None:
                raise ValueError("question_id cannot be null")

            get_object_or_404(ScreeningQuestionModel, pk = request.query_params.get("question_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "question_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class BenefitsView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            benefits = BenefitsModel.objects.all()
            if request.query_params.get("start") is not None:
                benefits = benefits.filter(Q(benefit__startswith = request.query_params.get("start").replace(" ", "_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "benefits" : list(map(lambda x: {"id":x[0],"name" : x[1].replace("_", " ").title()},benefits.values_list("id", "benefit"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("benefit") is None:
                raise ValueError("benefit field cannot be null")
            
            the_name = request.data.get("benefit")
            the_name = the_name.lower().replace(" ","_")
                        
            BenefitsModel.objects.create(benefit = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "benefit",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["benefit", "benefit_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
                
            the_benefit = get_object_or_404(BenefitsModel, pk = request.data.get("benefit_id"))
            the_name = request.data.get("benefit")
            the_name = the_name.lower().replace(" ","_")
            the_benefit.benefit = the_name
            the_benefit.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "benefit_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("benefit_id") is None:
                raise ValueError("benefit_id cannot be null")

            get_object_or_404(BenefitsModel, pk = request.query_params.get("benefit_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "benefit_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class SupplimentalView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [CustomIsAdmin()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            suppliments = SupplimentalPayModel.objects.all()
            if request.query_params.get("start") is not None:
                suppliments = suppliments.filter(Q(supplimentary__startswith = request.query_params.get("start").replace(" ", "_")))
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : {
                    "Supplimental Pay" : list(map(lambda x: {"id":x[0],"name": x[1].replace("_", " ").title()},suppliments.values_list("id", "supplimentary"))),
                }
                },status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if request.data.get("supplimentary") is None:
                raise ValueError("supplimentary field cannot be null")
            
            the_name = request.data.get("supplimentary")
            the_name = the_name.lower().replace(" ","_")
                        
            SupplimentalPayModel.objects.create(supplimentary = the_name)
            return Response({
                "status" : "success" , 
                "code" : "201", 
                "message" : "CREATED", 
                },status=status.HTTP_201_CREATED)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "benefit",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def put(self,request):
        try:
            required_fields = ["supplimentary", "supplimentary_id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise ValueError(f"{the_field} field cannot be null")
                
            the_suppliment = get_object_or_404(SupplimentalPayModel, pk = request.data.get("supplimentary_id"))
            the_name = request.data.get("supplimentary")
            the_name = the_name.lower().replace(" ","_")
            the_suppliment.supplimentary = the_name
            the_suppliment.save()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "UPDATED", 
                },status=status.HTTP_200_OK)
        
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "supplimentary_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        try:
            if request.query_params.get("supplimentary_id") is None:
                raise ValueError("supplimentary_id cannot be null")

            get_object_or_404(SupplimentalPayModel, pk = request.query_params.get("supplimentary_id")).delete()
            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "DELETED", 
            },status=status.HTTP_200_OK)
        except ValueError as v:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(v)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "400", 
                "message" : f"{self.request.method} failed", 
                "data" : { 
                        "errors" : [{
                            "field" : "supplimentary_id",
                            "message" : str(v)
                        }
                        ]
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : f"{self.request.method} failed", 
                "error" : str(e)
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)


#========================================================== User Details -> User-POV ==========================================================

class UserDetailsView(APIView):
    
    def get_permissions(self):
        if self.request.method == "GET":
            return [OnlyUserPermission()]
        if self.request.method == "POST":
            return [OnlyUserPermission()]
            #return [CustomPermission(request= self.request, codename="add_userdetailsmodel") or CustomPermission(request= self.request, codename="change_userdetailsmodel") ]
        return [CustomIsAuthenticated()]

    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            verified_user = authenticator(request)
            if verified_user is False:
                raise Exception("Authentication details not provided")
            user_details = UserDetailsModel.objects.filter(user = verified_user)
            user_project = UserProjectModel.objects.filter(user = verified_user)
            user_language = UserLanguageModel.objects.filter(user = verified_user)
            user_professional_details = UserProfessionalDetailsModel.objects.filter(user = verified_user)
            user_skills = UserSkillModel.objects.filter(user = verified_user).values_list("skill","skill_id__skill")
            user_certificate = UserCertificateModel.objects.filter(user = verified_user).values()
            user_education = UserEducationDetailsModel.objects.filter(user = verified_user).values()

            final_response = {}
            percent = 0

            if(user_project.exists()):
                percent += 14.285
                data = []
                for project in user_project:
                    data.append({
                        "id" : project.pk,
                        "title" : project.name,
                        "designation" : project.designation.designation,
                        "description" : project.description,
                        "document" : project.document.name,
                        "document_link" : project.document_link,
                        "project_skills" : list(map(lambda x : {"id" : x[0], "name" : x[1].replace("_", " ").title()},ProjectSkillModel.objects.filter(project = project.pk).values_list("skill", "skill__skill")))
                    })
                
                final_response.update({"user_projects" : data})

            if(user_language.exists()):
                percent += 14.285
                data = []
                for i in user_language:
                    data.append({
                        "id" : i.language.pk,
                        "language" : i.language.language,
                        "proficiency" : i.proficiency,
                        "read" : i.read,
                        "write" : i.write,
                        "speak" : i.speak,
                    })
                
                final_response.update({"user_languages" : data})

            if(user_skills.exists()) : 
                percent += 14.285
                final_response.update({"user_skills" : list(map(lambda x : {"id" : x[0], "name" : x[1].replace("_", " ").title()},user_skills))})

            if(user_professional_details.exists()) : 
                percent += 14.285
                prof_serialiser = UserProfessionalGetSerializer(user_professional_details, many=True) 
                final_response.update({"professional_details" : prof_serialiser.data})

            if(user_certificate.exists()) : 
                percent += 14.285           
                final_response.update({"certificate_details" : list(user_certificate)})

            if(user_education.exists()) : 
                percent += 14.285           
                final_response.update({"education_details" : list(user_education)})

            if(user_details.exists()):
                percent += 14.285
                val = user_details.first()
                user_details = user_details.values()[0]
                user_details.update({
                    # "id" : val.pk,
                    "user_id" : {
                        "name" : val.user.name,
                        "email" : val.user.email,
                        "mobile" : val.user.mobile,
                        "photo" : val.user.photo.name,
                    },
                "designation_id" : {
                    "id" : val.designation.pk,
                    "designation" : val.designation.designation,
                } if (val.designation is not None and val.designation != '') else '',
                "current_city_id" : {"id" : val.current_city.pk, "city" : val.current_city.city, "state" : val.current_city.state.state} if (val.current_city is not None and val.current_city != '') else '',
                "preferred_city_id" : {"id" : val.preferred_city.pk, "city" : val.preferred_city.city, "state" : val.preferred_city.state.state} if (val.preferred_city is not None and val.preferred_city != '') else '',
                "industry_id" : {"id" : val.industry.pk, "industry" : val.industry.industry, "image" : val.industry.image.name}  if (val.industry is not None and val.industry != '') else '',
                "resume" : val.resume.name
                })
                final_response.update({"user_details" : user_details})

            final_response.update({"percentage" : math.ceil(percent)})

            return Response({
                "status" : "success" , 
                "code" : "200", 
                "message" : "OK", 
                "data" : final_response
                },status=status.HTTP_200_OK)
        
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try: 
            verified_user = authenticator(request) 
            if(verified_user is False):
                raise Exception("Authentication credentials were not provided")  
            if verified_user.is_staff or verified_user.is_company:
                raise Exception("Admin or Company person cannot access this url")  
                  
            user_details = UserDetailsModel.objects.filter(user = verified_user)

            updated_data = request.data.copy()
            updated_data.update({"user" : verified_user.pk})

            if(user_details.exists()):
                serializer = UserDetailPostSerialiser(user_details.first(), data = updated_data)
            else:
                serializer = UserDetailPostSerialiser(data= updated_data)
            
            user_serialiser = UserProfilePostSerialiser(verified_user, data=request.data)
            
            if(serializer.is_valid() and user_serialiser.is_valid()):
                if request.data.get("photo") is not None:
                    verified_user.photo = request.data.get("photo")
                    verified_user.save()

                serializer.save()
                user_serialiser.save()
                return Response({
                    "status" : "success" , 
                    "code" : "200", 
                    "message" : "OK", 
                    },status=status.HTTP_200_OK)
            else:
                if(serializer.is_valid()):
                    pass
                else:
                    logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(serializer.errors)}')
                if(user_serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(user_serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serializer, user_serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(["POST"])
@permission_classes([OnlyUserPermission])
def UserResumeView(request):
    try:
        logger.info(f'Reqest for UserResumeView_ using POST method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')

        if((request.data.get("resume") is None) and (request.data.get("objective") is None) and (request.data.get("skills") is None)):
            raise ValueError("Either Resume or Objective or Skills field should be present")
        
        verified_user = authenticator(request)
        if(verified_user is False):
            raise Exception("Authentication details were not provided")
        if(request.data.get("resume") is not None):
            the_user, created = UserDetailsModel.objects.get_or_create(user = verified_user)
            the_user.resume = request.data.get("resume")
            the_user.save()

        if(request.data.get("objective") is not None):
            the_user, created = UserDetailsModel.objects.get_or_create(user = verified_user)
            the_user.objective = request.data.get("objective")
            the_user.save()
    
        if(request.data.get("skills") is not None):
            all_skills = set(request.data.get("skills", []))
            pre_user_skills = set(UserSkillModel.objects.filter(user = verified_user).values_list("skill", flat=True))
            to_delete_skills = pre_user_skills - all_skills
            new_skills = all_skills - pre_user_skills
            
            UserSkillModel.objects.filter(user= verified_user.pk, skill__in=to_delete_skills).delete()
            skillsets = [UserSkillModel(user = verified_user, skill = get_object_or_404(SkillsModel, pk = the_skill)) for the_skill in new_skills]
            UserSkillModel.objects.bulk_create(skillsets)
            
            # for skill in to_delete_skills:
            #     UserSkillModel.objects.get(user = request.user.pk, skill = skill).delete()
            # skillsets = [UserSkillModel(user = request.user, skill = get_object_or_404(SkillsModel, pk = the_skill)) for the_skill in all_skills if the_skill not in pre_user_skills]
            # UserSkillModel.objects.bulk_create(skillsets)

        return Response({
            "status" : "success",
            "code" : "200",
            "message" : "UPDATED"
        }, status=status.HTTP_200_OK)

    except ValueError as v:
        logger.error(f'Error in UserResumeView_ from POST method : {str(v)}')
        return Response(
            {
            "status" : "error" , 
            "code" : "400", 
            "message" : f"POST method failed", 
            "data" : { 
                    "errors" : [{
                        "field" : "organization or resume or skills",
                        "message" : str(v)
                    }
                    ]
                }
            },status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        logger.error(f'Error in UserResumeView_ from POST method : {str(e)}')
        return Response(
            {
            "status" : "error" , 
            "code" : "500", 
            "message" : f"POST method failed", 
            "error" : str(e)
            },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(["POST"])
@permission_classes([OnlyUserPermission])
def UserBasicView(request):
    try:
        verified_user = authenticator(request)
        if(verified_user is False):
            raise Exception("Authentication credentials were not provided")
        the_data = UserDetailsModel.objects.filter(user = verified_user.pk)
        updated_data = request.data.copy()
        updated_data.update({"user" : verified_user.pk})
        if(the_data.exists()):
            serialiser = UserDetailPostSerialiser2(the_data.first(), data = updated_data)
        else:
            serialiser = UserDetailPostSerialiser2(data=updated_data)
        
        if(serialiser.is_valid()):
            serialiser.save()
            return Response({
                "status" : "success",
                "code" : "200",
                "message" : "OK"
            }, status=status.HTTP_200_OK)
        else:
            if(serialiser.is_valid()):
                pass
            else:
                logger.error(f'Error in UserBasicView_ from POST method : {str(serialiser.errors)}')
            return Response(
                {
                    "status" : "error" , 
                    "code" : "400", 
                    "message" : "Invalid Data",
                    "data" : { 
                        "errors" : serialiser_errors([serialiser])
                    }
                },status=status.HTTP_400_BAD_REQUEST)
        
    except Exception as e:
        logger.error(f'Error in UserBasicView_ from POST method : {str(e)}')
        return Response(
        {
            "status" : "error" , 
            "code" : "500", 
            "message" : str(e), 
        },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class UserEducationView(APIView):
    def get_permissions(self):
        if self.request.method == "POST":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="add_usereducationmodel")]
        if self.request.method == "PUT":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="change_usereducationmodel")]
        if self.request.method == "DELETE":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="delete_usereducationmodel")]
        return [CustomIsAdmin()]

    # def get(self,request):
    #         pass
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentials were not provided")
            updated_data = request.data.copy()
            updated_data.update({"user" : verified_user.pk})
            serialiser = UserEducationSerialiser(data = updated_data)
            if (serialiser.is_valid()):
                serialiser.save()

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in UserBasicView_ from POST method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def put(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.data.get("id") is None):
                raise ValueError("id field cannt be null")
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentials were not provided")
            the_data = get_object_or_404(UserEducationDetailsModel, pk = request.data.get("id"), user = verified_user.pk)
            updated_data = request.data.copy()
            updated_data.update({"user" : verified_user.pk})
            serialiser = UserEducationSerialiser(the_data, data = updated_data)
            if (serialiser.is_valid()):
                serialiser.save()

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in UserBasicView_ from POST method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def delete(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.query_params.get("id") in None):
                raise ValueError("id field cannt be null")
            get_object_or_404(UserEducationDetailsModel, pk = request.query_params.get("id")).delete()
            return Response({
                "status" : "success", 
                "code" : "200",
                "message" : "OK"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserEmploymentView(APIView):
    def get_permissions(self):
        if self.request.method == "POST":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="add_professionalskillmodel")]
        if self.request.method == "PUT":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="change_professionalskillmodel")]
        if self.request.method == "DELETE":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="delete_professionalskillmodel")]
        return [CustomIsAdmin()]

    # def get(self,request):
    #         pass
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            verified_user = authenticator(request)
            if verified_user is False:
                raise Exception("Authentication credentials were not provided")
            updated_data = request.data.copy()
            updated_data.update({"user" : verified_user.pk})
            serialiser = UserEmploymentSerialiser(data = updated_data)
            if (serialiser.is_valid()):
                serialiser.save()

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in UserBasicView_ from POST method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def put(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.data.get("id") in None):
                raise ValueError("id field cannt be null")
            verified_user = authenticator(request)
            if verified_user is False:
                raise Exception("Authentication credentials were not provided")
            
            the_data = get_object_or_404(UserProfessionalDetailsModel, pk = request.data.get("id"))
            updated_data = request.data.copy()
            updated_data.update({"user" : verified_user.pk})
            serialiser = UserEmploymentSerialiser(the_data, data = updated_data)
            if (serialiser.is_valid()):
                serialiser.save()

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in UserBasicView_ from POST method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def delete(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.query_params.get("id") in None):
                raise ValueError("id field cannt be null")
            get_object_or_404(UserEmploymentSerialiser, pk = request.query_params.get("id")).delete()
            return Response({
                "status" : "success", 
                "code" : "200",
                "message" : "OK"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class UserProjectView(APIView):
    def get_permissions(self):
        if self.request.method == "POST":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="add_userprojectmodel")]
        if self.request.method == "PUT":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="change_userprojectmodel")]
        if self.request.method == "DELETE":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="delete_userprojectmodel")]
        return [CustomIsAdmin()]

    # def get(self,request):
    #         pass
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.data.get("skills") is None):
                raise Exception("skills field is required")
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentials were not provided")
            updated_data = request.data.copy()
            updated_data.update({"user" : verified_user.pk})
            serialiser = UserProjectSerialiser(data = updated_data)
            if (serialiser.is_valid()):
                saved_data = serialiser.save()
                skillset = [ProjectSkillModel(project = saved_data, skill = get_object_or_404(SkillsModel, pk = the_skill)) for the_skill in request.data.get('skills')]
                UserSkillModel.objects.bulk_create(skillset)

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in UserBasicView_ from POST method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def put(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.data.get("id") in None):
                raise ValueError("id field cannt be null")
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentials were not provided")
            
            the_data = get_object_or_404(UserProfessionalDetailsModel, pk = request.data.get("id"))
            updated_data = request.data.copy()
            updated_data.update({"user" : verified_user.pk})
            serialiser = UserEmploymentSerialiser(the_data, data = updated_data)
            if (serialiser.is_valid()):
                saved_data = serialiser.save()

                all_skills = set(request.data.get("skills",[]))
                pre_project_skills = set(ProjectSkillModel.objects.filter(project = request.data.get("id")).values_list("skill", flat=True))
                to_delete_skills = pre_project_skills - all_skills
                new_skills = all_skills - pre_project_skills

                ProjectSkillModel.objects.filter(project = request.data.get("id"), skill__in=to_delete_skills).delete()
                skillsets = [ProjectSkillModel(project = saved_data, skill = get_object_or_404(SkillsModel,pk = the_skill)) for the_skill in new_skills]
                ProjectSkillModel.objects.bulk_create(skillsets)

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in UserBasicView_ from POST method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def delete(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.query_params.get("id") in None):
                raise ValueError("id field cannt be null")
            get_object_or_404(UserProjectModel, pk = request.query_params.get("id")).delete()
            return Response({
                "status" : "success", 
                "code" : "200",
                "message" : "OK"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
  
class UserLanguageView(APIView):
    def get_permissions(self):
        if self.request.method == "POST":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="add_userlanguagemodel")]
        if self.request.method == "PUT":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="change_userlanguagemodel")]
        if self.request.method == "DELETE":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="delete_userlanguagemodel")]
        return [CustomIsAdmin()]

    # def get(self,request):
    #         pass
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.data.get("data_list") is None):
                raise ValueError("data_list field cannot be null")
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentails were not provided")
            
            updated_data = request.data.get("data_list")
            for data in updated_data:
                data.update({"user" : verified_user.pk})

            serialiser = UserLanguageSerialser(data = updated_data, many=True)
            if (serialiser.is_valid()):
                serialiser.save()

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in UserBasicView_ from POST method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def put(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.data.get("id") in None):
                raise ValueError("id field cannt be null")
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentails were not provided")
            the_data = get_object_or_404(UserLanguageModel, pk = request.data.get("id"))
            updated_data = request.data.copy()
            updated_data.update({"user" : verified_user.pk})
            serialiser = UserLanguageSerialser(the_data, data = updated_data)
            if (serialiser.is_valid()):
                serialiser.save()

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in UserBasicView_ from POST method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def delete(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            if(request.query_params.get("id") in None):
                raise ValueError("id field cannt be null")
            get_object_or_404(UserLanguageModel, pk = request.query_params.get("id")).delete()
            return Response({
                "status" : "success", 
                "code" : "200",
                "message" : "OK"
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

#========================================================== Recruiter-Company ==========================================================

# @api_view(["POST"])
# def CreateSub(request):

class CompanyDetailsView(APIView):
    def get_permissions(self):
        if self.request.method not in SAFE_METHODS:
            return [OnlyCompanyPermission()]
        return [CustomIsAdmin()]
    
    # def get(self,request):
    #     pass

    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            verified_user = authenticator(request)
            if verified_user is False:
                raise Exception("Authentication credentials were not provided")
            if not verified_user.is_company:
                raise Exception("Only a Company person can access this API")
            
            if request.data.get('organization_email') is None:
                raise Exception("oraganization_email field cannot be null")
            
            the_company = CompanyDetailsModel.objects.filter(organzation_email = request.data.get('organization_email'))
            
            updated_data = request.data.copy()
            updated_data.update({"user" : verified_user.pk})

            if the_company.exists():
                serialiser = CompanyPostSerializer(the_company.first(), data = updated_data)
            else:
                serialiser = CompanyPostSerializer(data = updated_data)

            if serialiser.is_valid():
                serialiser.save()
                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RecruiterActions(APIView):
    def get_permissions(self):
        if(self.request.method == "GET"):
            return [CompanyRecruiterPermission()]
        return [CustomIsAuthenticated()]

    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:    
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication Credentials were not provided")    
            all_jobs = JobsModel.objects.filter(user = verified_user.pk)

            if request.query_params.get("id") is not None:
                all_jobs = all_jobs.filter(pk = request.query_params.get("id"))
            
            all_applications = JobApplicationModel.objects.filter(job__user = verified_user.pk).order_by("-created_at")

            result = []
            for application in all_applications:
                application_job = model_to_dict(application.job)
                application_job.update({
                        "company" : {
                            "id" : application.job.company.pk,
                            "name" : application.job.company.organization_name,
                            "email" : application.job.company.organization_email,
                            "mobile" : application.job.company.organization_mobile,
                            "alternate_mobile" : application.job.company.alternate_mobile,
                            "address" : application.job.company.organization_address,
                            "logo" : application.job.company.organization_logo.name,
                            "website" : application.job.company.organization_website,
                            "industry" : application.job.company.industry.industry,
                            "description" : application.job.company.organization_description
                        },
                        "industry" : {"id" : application.job.industry.pk, "industry" : application.job.industry.industry, "iamge" : application.job.industry.image.name},
                        "city" : {"id" : application.job.city.pk, "city" : application.job.city.city},
                        "designation" : {"id" : application.job.designation.pk, "designation" : application.job.designation.designation},
                        "posted_at" : application.job.created_at,
                        "required_skills" : application.job.jobrequriedskillsmodel_set.values_list("skill", "skill__skill"),
                        "job_tags" : application.job.jobtagsmodel_set.values_list("tag", "tag__name"),
                        "number_of_applicants" : len(application.job.jobapplicationmodel_set.values()),
                        "start_salary" : application.job.start_salary if application.job.show_salary is True else '',
                        "end_salary" : application.job.end_salary if application.job.show_salary is True else '',
                    })
                result.append({
                    
                    "id" : application.pk,
                    "application_status" : application.status,
                    "applier" : {
                        "applier_name" : application.name,
                        "applier_email" : application.email,
                        "applier_mobile" : application.mobile,
                        "applier_photo" : application.user.photo.name,
                        "user_details" : application.user.userdetailsmodel_set.values(),
                    },
                    "job" : application_job

                })

            
            job_data = []
            for job in all_jobs:
                the_job = model_to_dict(job)
                the_job.update({
                    "company" : {
                        "id" : job.company.pk,
                        "name" : job.company.organization_name,
                        "email" : job.company.organization_email,
                        "mobile" : job.company.organization_mobile,
                        "alternate_mobile" : job.company.alternate_mobile,
                        "address" : job.company.organization_address,
                        "logo" : job.company.organization_logo.name,
                        "website" : job.company.organization_website,
                        "industry" : job.company.industry.industry,
                        "description" : job.company.organization_description,

                    },
                    "industry" : {"id" : job.industry.pk, "industry" : job.industry.industry, "image" : job.industry.image.name},
                    "city" : {"id" : job.city.pk, "city" : job.city.city},
                    "designation" : {"id" : job.designation.pk, "designation" : job.designation.designation},
                    "posted_at" : job.created_at,
                    "required_skills" : job.jobrequriedskillsmodel_set.values_list("skill", "skill__skill"),
                    "job_tags" : job.jobtagsmodel_set.values_list("tag", "tag__name"),
                    # "number_of_applicants" : len(job.jobapplicationmodel_set.values()),
                    "applicants" : job.jobapplicationmodel_set.values(),
                    "start_salary" : job.start_salary if job.show_salary is True else '',
                    "end_salary" : job.end_salary if job.show_salary is True else '',
                })
                job_data.append(the_job)
            
            verified_user = authenticator(request)
            if verified_user is False:
                raise Exception("Authentication credentials were not provided")
            if(verified_user.is_company):
                purchased_plan = get_object_or_404(PlanPurchasedModel, user = verified_user)
            else:
                purchased_plan = get_object_or_404(PlanPurchasedModel, user = verified_user.parent_user.pk)

            plan_data = user_plan_checker(purchased_plan)
                 
            return Response({
                "status" : "success",
                "code" : "200",
                "message" : "OK",
                "data" : {"jobs" : job_data, "recent_applications" : result, "plan_details" : plan_data }
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def post(self,request):
        pass

    def post(self,request):
        pass
#========================================================== Jobs ==========================================================

class JobsView(APIView):
    
    def get_permissions(self):
        if self.request.method == "POST":
            return [CustomPermission(request=self.request, codename="add_jobsmodel")]
        if self.request.method == "PUT":
            return [CustomPermission(request=self.request, codename="change_jobsmodel")]
        if self.request.method == "DELETE":
            return [CustomPermission(request=self.request, codename="delete_jobsmodel")]
        if self.request.method == 'GET':
            if self.request.query_params.get("user_designation") == 'true' or self.request.query_params.get("applied") == 'true':
                return [OnlyUserPermission()]
        return [AllowAny()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            all_jobs = JobsModel.objects.all()

            # if(request.query_params.get("dashboard") == "true"):
            #     complete_set = {
            #         "top_companies" : all_jobs.filter(company__is_top = True),
            #         "sponsored_companies" : all_jobs.filter(company__user__in = all_sponsors),
            #         "recent_companies" : all_jobs.order_by('-created_at')
            #     }

            if request.query_params.get("top") == 'true':
                all_jobs = all_jobs.filter(company__is_top = True)

            if request.query_params.get("user_designation") == 'true':
                verified_user = authenticator(request)
                all_jobs = all_jobs.filter(designation = get_object_or_404(UserDetailsModel, user = verified_user.pk).designation)

            if request.query_params.get("sponsored") == 'true':
                all_sponsors = PlanPurchasedModel.objects.filter(plan_period__amount__gt = 1).values_list("user",flat=True)
                all_jobs = all_jobs.filter(company__user__in = all_sponsors)
            
            if request.query_params.get("id") is not None:
                all_jobs = all_jobs.filter(pk = request.query_params.get("id"))

            if request.query_params.get("recent") == 'true':
                all_jobs = all_jobs.order_by('-created_at')
            
            if request.query_params.get("applied") == 'true':
                verified_user = authenticator(request)
                applied_jobs = JobApplicationModel.objects.filter(user = verified_user.pk).values_list("job", flat=True)
                all_jobs = all_jobs.filter(pk__in = applied_jobs)
            
            if request.query_params.get("designation") is not None:
                all_jobs = all_jobs.filter(designation = request.query_params.get("designation"))
            
            if request.query_params.get("city") is not None:
                all_jobs = all_jobs.filter(city = request.query_params.get("city"))
            
            data = []
            for job in all_jobs:
                auth = False
                verified_user = authenticator(request)
                saved = False
                if(verified_user):
                    auth = job.jobapplicationmodel_set.filter(user = verified_user.pk).exists()
                    saved = job.favoritesmodel_set.filter(user = verified_user.pk).exists()
                the_job = model_to_dict(job)
                the_job.update({
                    "company" : {
                        "id" : job.company.pk,
                        "name" : job.company.organization_name,
                        "email" : job.company.organization_email,
                        "mobile" : job.company.organization_mobile,
                        "alternate_mobile" : job.company.alternate_mobile,
                        "address" : job.company.organization_address,
                        "logo" : job.company.organization_logo.name,
                        "website" : job.company.organization_website,
                        "industry" : job.company.industry.industry,
                        "description" : job.company.organization_description
                    },
                    "industry" : {"id" : job.industry.pk, "industry" : job.industry.industry, "industry_image" : job.industry.image.name},
                    "city" : {"id" : job.city.pk, "city" : job.city.city},
                    "designation" : {"id" : job.designation.pk, "designation" : job.designation.designation},
                    "posted_at" : job.created_at,
                    "required_skills" : map(lambda x : {"id" : x[0], "name" : x[1]},job.jobrequriedskillsmodel_set.values_list("skill", "skill__skill")),
                    "job_tags" : map(lambda x : {"id" : x[0], "name" : x[1]},job.jobtagsmodel_set.values_list("tag", "tag__name")),
                    "number_of_applicants" : len(job.jobapplicationmodel_set.values()),
                    "start_salary" : job.start_salary if job.show_salary is True else '',
                    "end_salary" : job.end_salary if job.show_salary is True else '',
                    "applied" : int(auth),
                    "saved" : int(saved)
                })
                data.append(the_job)
                 
            return Response({
                "status" : "success",
                "code" : "200",
                "message" : "OK",
                "data" : data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:

            required_fields = ["required_skills", "required_questions", "required_tags"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise Exception(f"{the_field} field is cannot be null")
            
            verified_user = authenticator(request)
            if verified_user is False:
                raise Exception("Authentication credentials were not provided")
            if verified_user.is_company:
                purchased_plan = get_object_or_404(PlanPurchasedModel, user = verified_user.pk)
                the_company = get_object_or_404(CompanyDetailsModel, user = verified_user.pk)
                posted_jobs = JobsModel.objects.filter(company__user = verified_user.pk)

            else:
                purchased_plan = get_object_or_404(PlanPurchasedModel, user = verified_user.parent_user.pk)
                posted_jobs = JobsModel.objects.filter(company__user = verified_user.parent_user.pk)
                the_company = get_object_or_404(CompanyDetailsModel, user = verified_user.parent_user.pk)
            
            user_plan_vals = user_plan_checker(purchased_plan)

            if(len(posted_jobs) >= user_plan_vals["job_limit"]):
                raise Exception("Job posting limit exceeded")

            if(user_plan_vals["amount"] > 0):
                if(len([i for i in user_plan_vals["remaining_time"].values() if i<0]) > 0 or len([i for i in user_plan_vals["remaining_time"].values() if i == 0]) >= 6):
                    raise Exception("Plan Expired")

            updated_data = request.data.copy() 
            updated_data.update({"user" : verified_user.pk, "company" : the_company.pk})   
            serialiser = JobPostSerialiser(data = updated_data)

            if(serialiser.is_valid()):
                the_data = serialiser.save()

                if(len(request.data.get("required_skills")[0]) != 2):
                    raise Exception("Expected required_skills = [[skill_id, requirement]]")
                required_skills = [JobRequriedSkillsModel(job = the_data.pk, skill = skills[0], requirement = skills[1]) for skills in request.data.get("required_skills")]
                JobRequriedSkillsModel.objects.bulk_create(required_skills)

                required_tags = [JobTagsModel(job = the_data.pk, tag = tag) for tag in request.data.get("   ")]
                JobTagsModel.objects.bulk_create(required_tags)

                if(len(request.data.get("required_questions")[0]) != 3):
                    raise Exception("Expected required_questions = [[question_id, answer, type]]")
                required_questions = [JobScreeningQuestionModel(job = the_data.pk, question = question[0], answer = question[1], type = question[2]) for question in request.data.get("required_questions")]
                JobScreeningQuestionModel.objects.bulk_create(required_questions)

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)

            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:

            required_fields = ["required_skills", "required_questions", "required_tags", "id"]
            for the_field in required_fields:
                if request.data.get(the_field) is None:
                    raise Exception(f"{the_field} field is cannot be null")
            
            verified_user = authenticator(request)
            if verified_user is False:
                raise Exception("Authentication credentials were not provided")
            if verified_user.is_company:
                purchased_plan = get_object_or_404(PlanPurchasedModel, user = verified_user.pk)
                the_company = get_object_or_404(CompanyDetailsModel, user = verified_user.pk)
                posted_jobs = JobsModel.objects.filter(company__user = verified_user.pk)

            else:
                purchased_plan = get_object_or_404(PlanPurchasedModel, user = verified_user.parent_user.pk)
                posted_jobs = JobsModel.objects.filter(company__user = verified_user.parent_user.pk)
                the_company = get_object_or_404(CompanyDetailsModel, user = verified_user.parent_user.pk)
            
            user_plan_vals = user_plan_checker(purchased_plan)

            if(len(posted_jobs) >= user_plan_vals["job_limit"]):
                raise Exception("Job posting limit exceeded")

            if(user_plan_vals["amount"] > 0):
                if(len([i for i in user_plan_vals["remaining_time"].values() if i<0]) > 0 or len([i for i in user_plan_vals["remaining_time"].values() if i == 0]) >= 6):
                    raise Exception("Plan Expired")

            updated_data = request.data.copy() 
            updated_data.update({"user" : verified_user.pk, "company" : the_company.pk}) 
            the_job = get_object_or_404(JobsModel, pk = request.data.get("id"))  
            serialiser = JobPostSerialiser(the_job, data = updated_data)

            if(serialiser.is_valid()):
                the_data = serialiser.save()

                if(len(request.data.get("required_skills")[0]) != 2):
                    raise Exception("Expected required_skills = [[skill_id, requirement]]")
                required_skills = [JobRequriedSkillsModel(job = the_data.pk, skill = skills[0], requirement = skills[1]) for skills in request.data.get("required_skills")]
                JobRequriedSkillsModel.objects.bulk_update(required_skills, ["skill", "requirement"])

                required_tags = [JobTagsModel(job = the_data.pk, tag = tag) for tag in request.data.get("required_tags")]
                JobTagsModel.objects.bulk_update(required_tags, ["tag"])

                if(len(request.data.get("required_questions")[0]) != 3):
                    raise Exception("Expected required_questions = [[question_id, answer, type]]")
                required_questions = [JobScreeningQuestionModel(job = the_data.pk, question = question[0], answer = question[1], type = question[2]) for question in request.data.get("required_questions")]
                JobScreeningQuestionModel.objects.bulk_update(required_questions, ["question", "answer", "type"])

                return Response({
                    "status" : "success", 
                    "code" : "200",
                    "message" : "OK"
                }, status=status.HTTP_200_OK)
            else:
                if (serialiser.is_valid()):
                    pass
                else:
                    logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(serialiser.errors)}')
                return Response(
                    {
                        "status" : "error" , 
                        "code" : "400", 
                        "message" : "Invalid Data",
                        "data" : { 
                            "errors" : serialiser_errors([serialiser])
                            }
                    },status=status.HTTP_400_BAD_REQUEST)

            
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class JobApplicationView(APIView):

    def get_permissions(self):
        if self.request.method == "PUT":
            return [CustomPermission(request=self.request, codename="change_jobapplicationmodel")]
        if self.request.method == "POST":
            return [OnlyUserPermission()]
            # return [CustomPermission(request=self.request, codename="add_jobapplicationmodel")]

        return [CustomIsAuthenticated()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            all_applications = JobApplicationModel.objects.all()
            verified_user = authenticator(request)
            if(verified_user.is_company):
                all_applications = all_applications.filter(job__company = verified_user.companydetailsmodel_set.first().pk)
            elif(verified_user.parent_user is not None):
                all_applications = all_applications.filter(job__user = verified_user.pk)
            elif(verified_user.is_staff is False):
                all_applications.filter(user = verified_user.pk)
            
            if(request.query_params.get("id") is not None):
                all_applications = all_applications.filter(pk = request.query_params.get("id"))

            if(request.query_params.get("recent") == "true"):
                all_applications = all_applications.order_by("-created_at")
        
            result = []
            for application in all_applications:
                application_job = model_to_dict(application.job)
                application_job.update({
                        "company" : {
                            "id" : application.job.company.pk,
                            "name" : application.job.company.organization_name,
                            "email" : application.job.company.organization_email,
                            "mobile" : application.job.company.organization_mobile,
                            "alternate_mobile" : application.job.company.alternate_mobile,
                            "address" : application.job.company.organization_address,
                            "logo" : application.job.company.organization_logo.name,
                            "website" : application.job.company.organization_website,
                            "industry" : application.job.company.industry.industry,
                            "description" : application.job.company.organization_description
                        },
                        "industry" : {"id" : application.job.industry.pk, "industry" : application.job.industry.industry, "iamge" : application.job.industry.image.name},
                        "city" : {"id" : application.job.city.pk, "city" : application.job.city.city},
                        "designation" : {"id" : application.job.designation.pk, "designation" : application.job.designation.designation},
                        "posted_at" : application.job.created_at,
                        "required_skills" : application.job.jobrequriedskillsmodel_set.values_list("skill", "skill__skill"),
                        "job_tags" : application.job.jobtagsmodel_set.values_list("tag", "tag__name"),
                        "number_of_applicants" : len(application.job.jobapplicationmodel_set.values()),
                        "start_salary" : application.job.start_salary if application.job.show_salary is True else '',
                        "end_salary" : application.job.end_salary if application.job.show_salary is True else '',
                    })
                result.append({
                    
                    "id" : application.pk,
                    "applied_at" : application.created_at,
                    "application_status" : application.status,
                    "applier" : {
                        "applier_name" : application.name,
                        "applier_email" : application.email,
                        "applier_mobile" : application.mobile,
                        "applier_photo" : application.user.photo.name,
                        "user_details" : application.user.userdetailsmodel_set.values(),
                    },
                    "job" : application_job

                })
            return Response({
                "status" : "success",
                "code" : "200",
                "message" : "OK",
                "data" : result
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def post(self,request):
        try:
            required_fields = ["name", "email", "mobile", "job"]
            for the_field in required_fields:
                if(request.data.get(the_field) is None):
                    raise Exception(f"{the_field} field cannot be null")
            
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentials were not provided")
            
            user_details = verified_user.userdetailsmodel_set
            if (user_details.exists() == False):
                raise Exception("User Details are empty")
            
            user_detailsFirst = user_details.first()
            if(request.data.get("resume") is not None):
                user_detailsFirst.resume = request.data.get("resume")
                user_detailsFirst.save()
            
            if(user_detailsFirst.resume is None or user_detailsFirst.resume == ''):
                raise Exception("User Resume cannot be null")

            JobApplicationModel.objects.create(name = request.data.get("name"), email = request.data.get("email"), mobile = request.data.get("mobile"), user = verified_user, job = get_object_or_404(JobsModel,pk = request.data.get("job")))
            return Response({
                "status" : "success",
                "code" : "201",
                "message" : "CREATED",
            }, status=status.HTTP_201_CREATED)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def put(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            required_fields = ["id", "status"]
            for the_field in required_fields:
                if request.data.get(the_field):
                    raise Exception(f"{the_field} field cannot be null")
            the_application = get_object_or_404(JobApplicationModel, pk = request.data.get("id"))
            the_application.status = request.data.get("status")
            the_application.save()
            return Response({
                "status" : "success",
                "code" : "200",
                "message" : "OK",
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def delete(self,request):
        pass

class FavoritesView(APIView):
    def get_permissions(self):
        return [OnlyUserPermission()]
    
    def get(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentials were not provided")
            
            all_jobs = JobsModel.objects.filter(favoritesmodel__user = verified_user.pk)
            data = []
            for job in all_jobs:
                the_job = model_to_dict(job)
                the_job.update({
                    "company" : {
                        "id" : job.company.pk,
                        "name" : job.company.organization_name,
                        "email" : job.company.organization_email,
                        "mobile" : job.company.organization_mobile,
                        "alternate_mobile" : job.company.alternate_mobile,
                        "address" : job.company.organization_address,
                        "logo" : job.company.organization_logo.name,
                        "website" : job.company.organization_website,
                        "industry" : job.company.industry.industry,
                        "description" : job.company.organization_description
                    },
                    "industry" : {"id" : job.industry.pk, "industry" : job.industry.industry, "industry" : job.industry.image.name},
                    "city" : {"id" : job.city.pk, "city" : job.city.city},
                    "designation" : {"id" : job.designation.pk, "designation" : job.designation.designation},
                    "posted_at" : job.created_at,
                    "required_skills" : map(lambda x : {"id" : x[0], "name" : x[1]},job.jobrequriedskillsmodel_set.values_list("skill", "skill__skill")),
                    "job_tags" : map(lambda x : {"id" : x[0], "name" : x[1]},job.jobtagsmodel_set.values_list("tag", "tag__name")),
                    # "number_of_applicants" : len(job.jobapplicationmodel_set.values()),
                    "start_salary" : job.start_salary if job.show_salary is True else '',
                    "end_salary" : job.end_salary if job.show_salary is True else '',
                    "applied" : int(job.jobapplicationmodel_set.filter(user = verified_user.pk).exists()),
                })
                data.append(the_job)
                 
            return Response({
                "status" : "success",
                "code" : "200",
                "message" : "OK",
                "data" : data
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
    def post(self,request):
        logger.info(f'Reqest for {self.__class__.__name__} using {self.request.method} method : qp={str(request.query_params)}, data={str(request.data)}, head={str(request.headers)}')
        try:
            required_fields = ["job_id"]
            for field in required_fields:
                if request.data.get(field) is None:
                    raise Exception(f"{field} field cannot be null")
            verified_user = authenticator(request)
            if(verified_user is False):
                raise Exception("Authentication credentials were not provided")
            
            favs = FavoritesModel.objects.filter(user = verified_user.pk, job = request.data.get("job_id"))
            if(favs.exists()):
                favs.first().delete()
            else:
                FavoritesModel.objects.create(user = verified_user, job = get_object_or_404(JobsModel,pk = request.data.get("job_id")))

            return Response({
                "status" : "success",
                "code" : "200",
                "message" : "OK",
            }, status=status.HTTP_200_OK)
        except Exception as e:
            logger.error(f'Error in {self.__class__.__name__} from {self.request.method} method : {str(e)}')
            return Response(
                {
                "status" : "error" , 
                "code" : "500", 
                "message" : str(e), 
                },status=status.HTTP_500_INTERNAL_SERVER_ERROR)