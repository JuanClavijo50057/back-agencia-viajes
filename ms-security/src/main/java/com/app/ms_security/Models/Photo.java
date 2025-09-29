package com.app.ms_security.Models;

import lombok.Data;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Data
@Document
public class Photo {
    @Id
    private String _id;
    private byte[] data;
    private String contentType;

    public Photo() {}

    public Photo(byte[] data, String contentType) {
        this.data = data;
        this.contentType = contentType;
    }
}
