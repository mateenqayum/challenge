from django.contrib import admin
from django.urls import path, include, re_path

from core.schema import schema_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('auth/', include('user.urls', namespace='user')),
    path('transaction/', include('transaction.urls', namespace='transaction')),
    re_path(r'^swagger(?P<format>\.json|\.yaml)$', schema_view.without_ui(cache_timeout=0), name='schema-json'),
    path('swagger/', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc', cache_timeout=0), name='schema-redoc'),
]
