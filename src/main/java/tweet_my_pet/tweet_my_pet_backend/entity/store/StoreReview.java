package tweet_my_pet.tweet_my_pet_backend.entity.store;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import tweet_my_pet.tweet_my_pet_backend.entity.User;

@Getter
@Setter
@Entity
@Table(name = "store_review")
public class StoreReview {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "store_review_id", nullable = false)
    private Long storeReviewId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "store_review_text", nullable = false)
    private String storeReviewText;

    @Column(name = "store_review_picture_bool", nullable = false)
    private Boolean storeReviewPictureBool = false;

}