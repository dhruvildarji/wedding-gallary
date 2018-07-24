web: python manage.py collectstatic --noinput
web: python manage.py makemigrations
web: python manage.py migrate
web: gunicorn wedding_gallary.wsgi
