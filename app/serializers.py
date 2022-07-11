from wsgiref import validate
from rest_framework import serializers
from .models import Profile,Project, Cohort, User,Member
from django.contrib.auth import get_user_model
User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model=User
        fields= ('name','username', 'email', 'password')
       
        extra_kwargs = {
            'password': {'write_only': True}
        }



    def create(self, validated_data):
        password = validated_data.pop('password', None)
        instance = self.Meta.model(**validated_data)

        if password is not None:
            instance.set_password(password)

        instance.save()
        return instance

class ProfileSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    def get_user(self, obj):
      return obj.user.username

    class Meta:
        model=Profile
        fields=('__all__')

        # read_only_fields = ("user",)
        # depth = 1



        
class ProjectSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()

    def get_user(self, obj):
      return obj.user.username

    member = serializers.SerializerMethodField()

    def get_member(self, obj):
      return obj.user.username

    class Meta:
        model = Project
        fields=('__all__') 
    

class CohortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cohort 
        fields = ('name', 'admission_date', 'graduation_date')

class MemberSerializer(serializers.ModelSerializer):
    member = serializers.SerializerMethodField()

    def get_member(self, obj):
      return obj.user.username
    class Meta:
        model = Member
        fields=('__all__') 

