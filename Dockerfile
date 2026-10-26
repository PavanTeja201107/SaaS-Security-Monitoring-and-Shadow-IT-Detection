# Run the complete SaaS Security Monitoring pipeline and Streamlit dashboard.
FROM python:3.12-slim

WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    MPLBACKEND=Agg \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./

EXPOSE 8501

# Results are regenerated from the fixed-seed datasets each time the container starts.
CMD ["sh", "-c", "python generate_data.py && python evaluate.py && python run_detections.py && python run_behavioral_baseline.py && python run_correlation.py && streamlit run app.py --server.address=0.0.0.0 --server.port=8501"]
