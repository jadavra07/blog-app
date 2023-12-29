package com.blog.controller;

import com.blog.payload.PostDto;
import com.blog.service.PostService;
import javax.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/posts")
public class PostController {

    private PostService postService;

    public PostController(PostService postService) {
        this.postService = postService;
    }

    //http://localhost:8080/api/posts?pageNo=0&pageSize=5&sortBy=title&sortDir=asc
    @GetMapping
    public ResponseEntity<List<PostDto>> getAllPost(
            @RequestParam(name = "pageNo", defaultValue = "0", required = false) int pageNO,
            @RequestParam(name = "pageSize", defaultValue = "5", required = false) int pageSize,
            @RequestParam(name = "sortBy", defaultValue = "id", required = false) String sortBy,
            @RequestParam(name = "sortDir", defaultValue = "asc", required = false) String sortDir

    ) {
        List<PostDto> postDtos = postService.getAllPost(pageNO, pageSize, sortBy, sortDir);
        return new ResponseEntity<>(postDtos, HttpStatus.OK);
    }



    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createPost(@Valid @RequestBody PostDto postDto, BindingResult bindingResult) {
        if (bindingResult.hasErrors()) {
            return new ResponseEntity<>(bindingResult.getFieldError().getDefaultMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
        PostDto dto = postService.createPost(postDto);
        return new ResponseEntity<>(dto, HttpStatus.OK);

    }

    //http://localhost:8080/api/posts?postId=1

    @PutMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<PostDto> updatePost(
            @RequestParam(name = "postId") long postId,
            @RequestBody  PostDto PostDto
    ) {
        PostDto dto = postService.UpdatePost(postId, PostDto);
        return new ResponseEntity<>(dto, HttpStatus.OK);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deletePost(@PathVariable long id) {
        postService.deletePost(id);
        return new ResponseEntity<>("delete", HttpStatus.CREATED);

    }

}

