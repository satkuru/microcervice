FROM python:3.9-alpine
WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY . .
EXPOSE 5010
CMD ["python","./services/products.py"]