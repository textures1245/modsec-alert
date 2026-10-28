# Verification box for install-modsec-patch.sh: stock OWASP CRS nginx image +
# python3 (needed by the patch's retire/audit) + a 200-everything stub backend.
# Built once and cached (verify.sh image); a box then starts in ~6s.
FROM owasp/modsecurity-crs:nginx
USER root
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends python3 \
 && rm -rf /var/lib/apt/lists/*
COPY stub-backend.py /opt/verify/stub-backend.py
USER nginx
