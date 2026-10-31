FROM php:8.3-apache

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
