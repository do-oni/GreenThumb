package com.ssh.greenthumb.api.domain.post;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.fasterxml.jackson.annotation.JsonManagedReference;
import com.ssh.greenthumb.api.domain.like.LikeComment;
import com.ssh.greenthumb.api.domain.user.User;
import com.ssh.greenthumb.api.common.domain.BaseTimeEntity;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.ArrayList;
import java.util.List;

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Getter
public class Comment extends BaseTimeEntity {

    @Id
    @Column(name = "comment_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JsonManagedReference
    @JoinColumn(name = "post")
    @NotNull
    private Post post;

    @ManyToOne
    @JsonManagedReference
    @JoinColumn(name = "user")
    @NotNull
    private User user;

    @JoinColumn(name = "comment_content", columnDefinition = "varchar(1500)")
    @NotNull
    private String content;

    @JoinColumn(name = "comment_delete")
    @NotNull
    private String isDeleted = "n";

    @OneToMany(mappedBy = "comment", cascade = CascadeType.ALL)
    @JsonBackReference
    private List<LikeComment> likeCommentList = new ArrayList<>();

    @Builder
    public Comment(Post post, User user, String content) {
        this.post = post;
        this.user = user;
        this.content = content;
    }

    public Comment update(String content) {
        this.content = content;

        return this;
    }

    public String delete() {
        this.isDeleted = "y";

        return this.isDeleted;
    }

}