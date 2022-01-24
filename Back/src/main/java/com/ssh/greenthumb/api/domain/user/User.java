package com.ssh.greenthumb.api.domain.user;

import com.fasterxml.jackson.annotation.JsonBackReference;
import com.ssh.greenthumb.api.common.domain.BaseTimeEntity;
import com.ssh.greenthumb.auth.domain.AuthProvider;
import com.ssh.greenthumb.auth.domain.Role;
import com.ssh.greenthumb.api.domain.plant.Plant;
import com.ssh.greenthumb.api.domain.post.Comment;
import com.ssh.greenthumb.api.domain.post.Post;
import com.ssh.greenthumb.auth.domain.RefreshToken;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@Entity
public class User extends BaseTimeEntity {

    @Id
    @Column(name = "user_id")
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column
    @NotNull
    private String email;

    @Column(name = "user_password")
    private String password;

    @Column(name = "user_nickname")
    @NotNull
    private String nickName;

    @Enumerated(EnumType.STRING)
    @NotNull
    private Role role = Role.USER;

    @Column(name = "user_delete")
    @NotNull
    private String isDeleted = "n";

    @Column(name = "user_black")
    @NotNull
    private String isBlack = "n";

    @Enumerated(EnumType.STRING)
    @NotNull
    private AuthProvider provider;

    @Column
    private String providerId;

    @Column
    private String imageUrl;

    @NotNull
    private Boolean emailVerified = false;

    @Column(name = "user_delete_date")
    private LocalDateTime deleteDate;

    @Column(name = "user_profile", columnDefinition = "varchar(900)")
    private String profile;

    @Column(name = "user_delete_reason", columnDefinition = "varchar(900)")
    private String deleteReason;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonBackReference
    private List<Plant> plantList = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonBackReference
    private List<Post> postList = new ArrayList<>();

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonBackReference
    private List<Comment> commentList = new ArrayList<>();

    @OneToMany(mappedBy = "follower", cascade = CascadeType.ALL)
    @JsonBackReference
    private Set<Follow> followerList = new HashSet<>();

    @OneToMany(mappedBy = "followee", cascade = CascadeType.ALL)
    @JsonBackReference
    private Set<Follow> followeeList = new HashSet<>();

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonBackReference
    private BlackList blackList;

    @OneToOne(mappedBy = "user", cascade = CascadeType.ALL)
    @JsonBackReference
    private RefreshToken refreshToken;

    @Builder
    public User(String email, String password, String nickName, String imageUrl, Role role, AuthProvider provider, String providerId) {
        this.email = email;
        this.password = password;
        this.nickName = nickName;
        this.imageUrl = imageUrl;
        this.role = role;
        this.provider = provider;
        this.providerId = providerId;
    }

    public User update(String nickName, String profile) {
        this.nickName = nickName;
        this.profile = profile;

        return this;
    }

    public User updateRole() {
        this.role = Role.ADMIN;

        return this;
    }

    public void blackUser() {
        this.isBlack = "y";
        this.role = Role.BLACK;
    }

    public void nonBlackUser() {
        this.isBlack = "n";
        this.role = Role.USER;
    }

    public void delete() {
        this.isDeleted = "y";
        this.role = Role.DELETE;
        this.deleteDate = LocalDateTime.now();
    }

}