from django.contrib import admin
from .models import Cohort ,Project,User,Profile,Member

# Register your models here.
admin.site.register(Cohort)
admin.site.register(Project)
admin.site.register(Profile)
admin.site.register(User)
admin.site.register(Member)
