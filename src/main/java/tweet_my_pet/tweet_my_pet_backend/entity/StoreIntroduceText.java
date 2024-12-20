package tweet_my_pet.tweet_my_pet_backend.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "store_introduce_text")
public class StoreIntroduceText {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "store_introduce_text_id", nullable = false)
    private Long storeIntroduceTextId;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(name = "store_introduce_id", nullable = false)
    private StoreIntroduce storeIntroduce;

    @Column(name = "store_introduce_text_content", nullable = false, length = Integer.MAX_VALUE)
    private String storeIntroduceTextContent;

}