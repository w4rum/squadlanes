FROM nginx:1.31.9-trixie

# Run as the unprivileged nginx user (uid 101) on port 8080,
# equivalent to what nginxinc/nginx-unprivileged does.
RUN sed -i 's/listen\s*80;/listen 8080;/; /listen\s*\[::\]:80;/d' /etc/nginx/conf.d/default.conf \
    && sed -i '/^user /d; s,^pid .*,pid /tmp/nginx.pid;,' /etc/nginx/nginx.conf \
    && sed -i '/^http {/a \    client_body_temp_path /tmp/client_temp;\n    proxy_temp_path /tmp/proxy_temp;\n    fastcgi_temp_path /tmp/fastcgi_temp;\n    uwsgi_temp_path /tmp/uwsgi_temp;\n    scgi_temp_path /tmp/scgi_temp;' /etc/nginx/nginx.conf \
    && chown -R nginx:nginx /var/cache/nginx /etc/nginx/conf.d \
    && nginx -t \
    && rm -rf /tmp/nginx.pid /tmp/*_temp

COPY --chown=root:root ./dist /usr/share/nginx/html

EXPOSE 8080
USER nginx
STOPSIGNAL SIGQUIT
