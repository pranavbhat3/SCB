FROM projectdiscovery/tlsx:v1.1.9

# Use a fixed UID/GID for the non-root user
RUN mkdir -p /app /home/securecodebox \
  && adduser --disabled-password --gecos '' --uid 1000 appuser \
  && chown -R appuser:appuser /app /home/securecodebox

COPY tlsx_wrapper.sh /app/tlsx_wrapper.sh
RUN chmod +x /app/tlsx_wrapper.sh

USER appuser
WORKDIR /home/securecodebox

ENTRYPOINT ["/app/tlsx_wrapper.sh"]
