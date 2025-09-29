package com.app.ms_security.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class Permission {
    @Id
    private String _id;
    private String url;
    private String method;
    private String model;


    public Permission(String url, String method, String model) {
        this.url = url;
        this.method = method;
        this.model = model;
    }
}
