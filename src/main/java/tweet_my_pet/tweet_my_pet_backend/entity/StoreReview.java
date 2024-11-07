package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "store_review", schema = "tweet_my_pet")
public class StoreReview {
    @Id
    @Column(name = "store_review_id", nullable = false)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "store_review_text", nullable = false)
    private String storeReviewText;

    @Column(name = "store_review_picture_bool", nullable = false)
    private Boolean storeReviewPictureBool = false;

}