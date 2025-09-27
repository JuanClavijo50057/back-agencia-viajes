package com.app.ms_security.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.DBRef;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class Profile {
    @Id
    private String _id;
    private String phone;

    @DBRef
    private User user;

    @DBRef
    private Photo photo;

    public Profile(String phone, User user, Photo photo) {
        this.phone = phone;
        this.user = user;
        this.photo = photo;
    }
}
