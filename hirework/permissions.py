from rest_framework.permissions import BasePermission
from django.shortcuts import get_object_or_404
from .models import UserModel
import jwt, os, datetime, logging
from dotenv import load_dotenv
load_dotenv()
SECRET_KEY = os.environ.get('SECRET_KEY')
logger = logging.getLogger(__name__)


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


class CustomIsAdmin(BasePermission):
    def has_permission(self, request, view):
        verified = Header_Checker(request)
        if(verified != False):
            return verified.get("is_staff") == True
        return False
    
class CustomIsAuthenticated(BasePermission):
    def has_permission(self, request, view):
        verified = Header_Checker(request)
        if(verified != False):
            return True
        return False


class CustomPermission(BasePermission):
    def __init__(self, request, codename):
        self.request = request
        self.permission_codename = codename
    
    def has_permission(self, request, view):
        verified = Header_Checker(self.request)
        if(verified != False):
            the_user = get_object_or_404(UserModel, pk = verified.get("user_id"))
            if(the_user.role):
                return the_user.role.permissions.filter(codename = self.permission_codename).exists()
        return False


class OnlyUserPermission(BasePermission):
    def has_permission(self, request, view):
        verified = Header_Checker(request)
        if(verified != False):
            if((verified.get("is_company") is False) and (verified.get("parent_user") is False)):
                return True
        return False
    
class OnlyCompanyPermission(BasePermission):
    def has_permission(self, request, view):
        verified = Header_Checker(request)
        if(verified != False):
            if((verified.get("is_company") is True) and (verified.get("is_staff") is False)):
                return True
        return False

class CompanyRecruiterPermission(BasePermission):
    def has_permission(self, request, view):
        verified = Header_Checker(request)
        if(verified != False):
            if(verified.get("is_staff") is False):
                if((verified.get("is_company") is True) or (verified("parent_user") is not None)):
                    return True
        return False

class OnlyUserRestriction(BasePermission):
    def has_permission(self, request, view):
        verified = Header_Checker(request)
        if(verified != False):
            if((verified.get("is_company") is True) or (verified.get("is_staff") is True) or (verified.get("parent_user") is True)):
                return True
        return False