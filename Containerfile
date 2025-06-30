FROM python:3.9-alpine

COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ./smtp2slack4qnap.py /app/smtp2slack4qnap.py
CMD ["python", "/app/smtp2slack4qnap.py"]
