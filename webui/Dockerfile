# By digest: a tag can be moved to other content, a digest cannot (Dependabot proposes new ones)
FROM php:8.5-apache@sha256:08af36df144462d84c7f16190557eec06cb9f656882685610b712a15eec54d46

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
