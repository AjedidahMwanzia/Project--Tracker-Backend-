
from django.http import Http404

import re

from django.shortcuts import redirect, render
from django.contrib import messages
from rest_framework.decorators import api_view
from app.forms import UserRegistrationForm
from .models import *
from django.http import JsonResponse
import cloudinary
import cloudinary.uploader
import cloudinary.api
from .forms import UserRegistrationForm, UserCreationForm
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed
from app.permissions import IsAdminOrReadOnly
from .models import  Profile,Project,Cohort, User
from .serializers import ProfileSerializer, UserSerializer,ProjectSerializer, CohortSerializer,MemberSerializer
from rest_framework import status
import jwt,datetime
from .forms import *
from django.contrib.auth import get_user_model
User = get_user_model()
from requests.structures import CaseInsensitiveDict


# Create your views here.
def home(request):
    return render(request,'index.html')

@api_view(['GET'])
def users(request):
    users=User.objects.all()
    serialized=UserSerializer(users,many=True)
    return Response(serialized.data)


class ProjectList(APIView):
    def get(self,request,format = None):
        all_projects = Project.objects.all()
        serializerdata = ProjectSerializer(all_projects,many = True)
        # print(serializerdata.data.members)
        return Response(serializerdata.data)

@api_view(['POST'])
def register_user(request):
    
    regex = "@([a-z\S]+)"
    result = re.split(regex,request.data['email'])
    if result[1] == "student.moringaschool.com" or result[1] == "moringaschool.com":
        user = User.objects.filter(username=request.data['username']).first()
        if user:
            return Response({'message': 'You have already registered! Please login'})
        else:
            serialized_user = UserSerializer(data=request.data)
            serialized_user.is_valid(raise_exception=True)
            serialized_user.save()
            serialized_user.data.update({'message': 'Success! Please log in'})
            return Response(serialized_user.data)
    else:
        return Response({'message': 'Please register using the school email'})


    
class LoginView(APIView):
    def post(self, request):
        username = request.data['username']
        password = request.data['password']

        user=User.objects.filter(username=username).first()

        if user is None:
            raise AuthenticationFailed('user not found')

        if not user.check_password(password):
            raise AuthenticationFailed('incorrect password')


        payload = {
            'id': user.id,
            'exp': datetime.datetime.now() + datetime.timedelta(minutes=120),
            'iat': datetime.datetime.now()
        }

        token = jwt.encode(payload, 'this87295is9874my8574secret', algorithm='HS256')
        response = Response()

        response.set_cookie(key='jwt', value=token, httponly=True)

        response.data ={
            'jwt': token
        }

        return response
@api_view(['GET'])
def authenticated_user(request):
    # auth = request.headers.get("Authorization")
    # headers["Accept"] = "application/json"
    # headers["Authorization"] = "Bearer {token}"
    # authorizatoion= headers["Authorization"]
    token = request.headers.get("Authorization").replace('Bearer ','')
    
    if not token:
        return Response({'message': 'No authenticated user found!'})
       
    try:
        payload = jwt.decode(token, 'this87295is9874my8574secret', algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return Response({'message': 'Authentication token expired'})

    user = User.objects.filter(id=payload['id']).first()
    serialized_user = UserSerializer(user)
    serialized_user.data.update({'message': 'User found'})
    return Response(serialized_user.data)


class UserView(APIView):
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('unauthenticated')

        try:
            payload = jwt.decode(token, 'secret', algorithms='HS256')
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('unauthenticated')




        user = User.objects.filter(id=payload['id']).first()
        serializer = UserSerializer(user)



 
        return Response(serializer.data)


class LogoutView(APIView):
    def get(self, request):
        response= Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'come again soon'
        }

        return response 

class RegisterView(APIView):
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)

class ProfileList(APIView):
    # permission_classes = (IsAdminOrReadOnly,)
    def get(self, request, format=None):
        all_profile = Profile.objects.all()
        serializers = ProfileSerializer(all_profile, many=True)
        return Response(serializers.data)
    def patch(self, request, format=None):
        serializers = ProfileSerializer(data=request.data)
        if serializers.is_valid():
            serializers.save()
            return Response(serializers.data, status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)

class UserList(APIView):
    # permission_classes = (IsAdminOrReadOnly,)
    def get(self, request, format=None):
        all_user = User.objects.all()
        serializers = UserSerializer(all_user, many=True)
        return Response(serializers.data)
    def post(self, request, format=None):
        serializers = UserSerializer(data=request.data)
        if serializers.is_valid():
            serializers.save()
            return Response(serializers.data, status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)

class CohortList(APIView):
    def get(self, request, format=None):
        all_cohorts = Cohort.objects.all()
        serializers = CohortSerializer(all_cohorts, many=True)
        permission_classes = (IsAdminOrReadOnly,)
        return Response(serializers.data)
    
    def post(self,request,format=None):
        serializers = CohortSerializer(data=request.data)
        if serializers.is_valid():
            serializers.save()
            return Response(serializers.data, status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)

class MemberList(APIView):
    def get(self, request, format=None):
        all_members = Member.objects.all()
        serializers = MemberSerializer(all_members, many=True)
        permission_classes = (IsAdminOrReadOnly,)
        return Response(serializers.data)
    
    def post(self,request,format=None):
        serializers = MemberSerializer(data=request.data)
        if serializers.is_valid():
            serializers.save()
            return Response(serializers.data, status=status.HTTP_201_CREATED)
        return Response(serializers.errors, status=status.HTTP_400_BAD_REQUEST)



class UserDescription(APIView):
    # permission_classes = (IsAdminOrReadOnly,)
    
    def get_user(self,request, pk):
        current_user = request.user
        user = User.objects.get(id = current_user.id)
        # profile=Profile.filter_profile_by_id(user.id)
        try:
            return User.objects.get(pk=pk)
        except User.DoesNotExist:
            return Http404

    def get(self, request, pk, format=None):
        user = self.get_user(pk)
        serializers = UserSerializer(user)
        return Response(serializers.data)