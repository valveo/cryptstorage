# By digest: a tag can be moved to other content, a digest cannot (Dependabot proposes new ones)
FROM php:8.3-apache@sha256:a800bbd2c0aa322702259ed475556b2cbc311076a8d3c4bba9bfe96838745472

# Enable HTTPS rewrite
RUN a2enmod rewrite ssl

# Copy source
COPY . /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html

# PHP session security
RUN echo "session.cookie_httponly = On"  >> /usr/local/etc/php/php.ini && \
    echo "session.cookie_secure = On"    >> /usr/local/etc/php/php.ini && \
    echo "session.use_strict_mode = On"  >> /usr/local/etc/php/php.ini && \
    echo "expose_php = Off"              >> /usr/local/etc/php/php.ini

EXPOSE 80
