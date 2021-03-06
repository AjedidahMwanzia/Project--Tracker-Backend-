from wsgiref import validate
from rest_framework import serializers
from .models import Profile,Project, Cohort, User,Member
from django.contrib.auth import get_user_model
User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    # project = serializers.SerializerMethodField()

    # def get_project(self, obj):
    #   return obj.project.name
    class Meta:
        model=User
        fields= ("__all__")
       
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


class MemberSerializer(serializers.ModelSerializer):
    
    user = serializers.SerializerMethodField()

    def get_user(self, obj):
      return obj.user.username

    project = "ProjectSerializer(source='project_set', many=True)"

    class Meta:
        model = Member
        fields=('__all__') 


        
class ProjectSerializer(serializers.ModelSerializer):
    user = serializers.SerializerMethodField()
    member = MemberSerializer(source='member_set', many=True)
    def get_user(self, obj):
      return obj.user.username

    # member = serializers.SerializerMethodField()

    # def get_member(self, obj):
    #   return obj.member_set.all().username
      
    class Meta:
        model = Project
        fields=('__all__') 
    

class CohortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Cohort 
        fields = ("__all__")

