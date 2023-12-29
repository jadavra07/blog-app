package com.blog.payload;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class PostDto {


    private long id;

    @NotEmpty
    @Size(min = 2)
    @Size(max = 2147483647)
    private String title;

    @NotEmpty
    @Size(min = 4)
    @Size(max = 2147483647)
    private String description;

    @NotEmpty
    @Size(min = 4)
    @Size(max = 2147483647)
    private String content;
    private String message;
}
